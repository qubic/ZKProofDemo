// gen_vectors <outdir> <computor_seeds.txt> <arbitrator_seed.txt> — writes test vectors; stock_qubic.c is the oracle.
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include "stock_shim.hpp"
#include "stock_patched.cpp"
#include "tutil.h"

typedef unsigned char u8;
static const char* MESSAGE = "Hello ZK, this is QUBIC.";

static std::string hexs(const u8* p, size_t n) { char b[4096]; hex_enc(p, n, b); return b; }

// Deterministic 55-char a-z seed from a tag.
static void derive_seed(const char* tag, int i, char seed[56]) {
    u8 s[64]; char t[32]; int n = snprintf(t, sizeof t, "%s:%d", tag, i);
    KangarooTwelve((u8*)t, (unsigned)n, s, 55);
    for (int k = 0; k < 55; k++) seed[k] = 'a' + s[k] % 26;
    seed[55] = 0;
}

struct Rec { int expected; u8 pub[32], sig[64], msg[32]; const char* note; };
static std::vector<Rec> recs;

static void add(int expected, const u8* pub, const u8* sig, const u8* msg, const char* note) {
    Rec r; r.expected = expected; r.note = note;
    memcpy(r.pub, pub, 32); memcpy(r.sig, sig, 64); memcpy(r.msg, msg, 32);
    int got = verify(r.pub, r.msg, r.sig) ? 1 : 0;
    if (got != expected) { fprintf(stderr, "ORACLE MISMATCH '%s': expected %d got %d\n", note, expected, got); exit(1); }
    recs.push_back(r);
}

static void keys_from_seed(const char* seed, u8 sub[32], u8 priv[32], u8 pub[32]) {
    if (!getSubseed((const u8*)seed, sub)) { fprintf(stderr, "bad seed %s\n", seed); exit(1); }
    getPrivateKey(sub, priv);
    getPublicKey(priv, pub);
}

static std::vector<std::string> read_seeds(const char* path) {
    std::vector<std::string> v; char line[512];
    FILE* f = fopen(path, "r"); if (!f) { perror(path); exit(1); }
    while (next_line(f, line, sizeof line)) v.push_back(line);
    fclose(f); return v;
}

int main(int argc, char** argv) {
    if (argc != 4) { fprintf(stderr, "usage: gen_vectors <outdir> <computor_seeds> <arbitrator_seed>\n"); return 2; }
    std::string out = argv[1];
    std::vector<std::string> cseeds = read_seeds(argv[2]), aseed = read_seeds(argv[3]);
    if (aseed.size() != 1) { fprintf(stderr, "arbitrator seed file must have 1 line\n"); return 1; }

    // ---- SchnorrQ: 8 valid + 8 invalid (all self-checked vs stock verify()) ----
    const int N = 8;
    for (int i = 0; i < N; i++) {
        char seed[56]; u8 sub[32], priv[32], pub[32], msg[32], sig[64];
        derive_seed("sk", i, seed); keys_from_seed(seed, sub, priv, pub);
        char t[32]; int n = snprintf(t, sizeof t, "msg:%d", i); KangarooTwelve((u8*)t, (unsigned)n, msg, 32);
        sign(sub, pub, msg, sig);
        add(1, pub, sig, msg, "valid");
    }
    char seed0[56]; u8 sub[32], priv[32], pk[32], msg[32], sig[64];
    derive_seed("sk", 0, seed0); keys_from_seed(seed0, sub, priv, pk);
    KangarooTwelve((u8*)"msg:0", 5, msg, 32); sign(sub, pk, msg, sig);
    { u8 s[64]; memcpy(s, sig, 64); s[40] ^= 1; add(0, pk, s, msg, "tampered-S"); }
    { u8 s[64]; memcpy(s, sig, 64); s[5]  ^= 1; add(0, pk, s, msg, "tampered-R"); }
    { u8 m[32]; KangarooTwelve((u8*)"msg:1", 5, m, 32); add(0, pk, sig, m, "wrong-message"); }
    { char sd[56]; u8 su[32], pr[32], pk2[32]; derive_seed("sk", 1, sd); keys_from_seed(sd, su, pr, pk2);
      add(0, pk2, sig, msg, "wrong-pubkey"); }
    { u8 s[64]; memcpy(s, sig, 64); s[15] |= 0x80; add(0, pk, s, msg, "sig-bit128-set"); }
    { u8 p[32]; memcpy(p, pk, 32); p[15] |= 0x80; add(0, p, sig, msg, "pk-bit128-set"); }
    { u8 s[64]; memcpy(s, sig, 64); unsigned long long* S = (unsigned long long*)(s + 32); unsigned char c = 0;
      c = _addcarry_u64(c, S[0], CURVE_ORDER_0, &S[0]); c = _addcarry_u64(c, S[1], CURVE_ORDER_1, &S[1]);
      c = _addcarry_u64(c, S[2], CURVE_ORDER_2, &S[2]); c = _addcarry_u64(c, S[3], CURVE_ORDER_3, &S[3]);
      add(0, pk, s, msg, "non-canonical-S+order"); }
    { u8 zp[32] = {0}, zs[64] = {0}, zm[32] = {0}; add(0, zp, zs, zm, "all-zero"); }

    FILE* f = fopen((out + "/schnorrq_vectors.txt").c_str(), "w");
    fprintf(f, "# expected pubHex sigHex digestHex note   (oracle: stock_qubic.c verify())\n");
    for (auto& r : recs)
        fprintf(f, "%d %s %s %s %s\n", r.expected, hexs(r.pub, 32).c_str(), hexs(r.sig, 64).c_str(), hexs(r.msg, 32).c_str(), r.note);
    fclose(f);

    // ---- K12: lengths 0..700, input = ptn(len) ----
    f = fopen((out + "/k12_vectors.txt").c_str(), "w");
    fprintf(f, "# len digestHex   input = ptn(len): bytes 00..FA repeated (K12 spec pattern)\n");
    for (unsigned len = 0; len <= 700; len++) {
        u8 in[701], d[32]; ptn(in, len);
        KangarooTwelve(in, len, d, 32);
        fprintf(f, "%u %s\n", len, hexs(d, 32).c_str());
    }
    fclose(f);

    // ---- keygen: every computor seed + arbitrator ----
    std::vector<std::string> all = cseeds; all.push_back(aseed[0]);
    f = fopen((out + "/keygen_vectors.txt").c_str(), "w");
    fprintf(f, "# seed subseedHex privHex pubHex identity   (last line = arbitrator)\n");
    for (auto& s : all) {
        u8 su[32], pr[32], pu[32]; CHAR16 id[61]; char idc[61];
        keys_from_seed(s.c_str(), su, pr, pu);
        getIdentity(pu, id, false); for (int i = 0; i < 61; i++) idc[i] = (char)id[i];
        fprintf(f, "%s %s %s %s %s\n", s.c_str(), hexs(su, 32).c_str(), hexs(pr, 32).c_str(), hexs(pu, 32).c_str(), idc);
    }
    fclose(f);

    // ---- sign: first 16 computors + arbitrator, two digests each ----
    f = fopen((out + "/sign_vectors.txt").c_str(), "w");
    fprintf(f, "# seed digestHex sigHex   (stock_qubic.c sign(); digest #1 = K12(\"%s\"))\n", MESSAGE);
    u8 dmsg[32]; KangarooTwelve((const u8*)MESSAGE, (unsigned)strlen(MESSAGE), dmsg, 32);
    int idx = 0;
    for (auto& s : all) {
        if (idx >= 16 && &s != &all.back()) { idx++; continue; }
        u8 su[32], pr[32], pu[32], d2[32], sg[64];
        keys_from_seed(s.c_str(), su, pr, pu);
        sign(su, pu, dmsg, sg); if (!verify(pu, dmsg, sg)) { fprintf(stderr, "self-check failed\n"); return 1; }
        fprintf(f, "%s %s %s\n", s.c_str(), hexs(dmsg, 32).c_str(), hexs(sg, 64).c_str());
        char t[32]; int n = snprintf(t, sizeof t, "sign:%d", idx); KangarooTwelve((u8*)t, (unsigned)n, d2, 32);
        sign(su, pu, d2, sg); if (!verify(pu, d2, sg)) { fprintf(stderr, "self-check failed\n"); return 1; }
        fprintf(f, "%s %s %s\n", s.c_str(), hexs(d2, 32).c_str(), hexs(sg, 64).c_str());
        idx++;
    }
    fclose(f);

    printf("gen_vectors: %zu schnorrq, 701 k12, %zu keygen, %d sign vectors -> %s\n",
           recs.size(), all.size(), 2 * 17, out.c_str());
    return 0;
}
