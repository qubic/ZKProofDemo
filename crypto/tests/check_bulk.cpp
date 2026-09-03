// Bulk differential test: stock reference vs portable lib, fixed-seed PRNG. CHECK_BULK_N sets iterations.
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include "riscv_qubic_crypto.h"
#include "tutil.h"
#include "stock_shim.hpp"
#include "stock_patched.cpp"       // stock oracle: KangarooTwelve, getSubseed, sign, verify

typedef unsigned char u8;
static uint64_t rng_state = 0x243F6A8885A308D3ULL;   // fixed seed
static uint64_t rnd() {                              // xorshift64*
    uint64_t x = rng_state;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    rng_state = x;
    return x * 0x2545F4914F6CDD1DULL;
}
static void rnd_bytes(u8* p, size_t n) {
    for (size_t i = 0; i < n; i++) p[i] = (u8)(rnd() >> 56);
}
static void print_triple(const u8* pub, const u8* sig, const u8* d) {
    char h[160];
    hex_enc(pub, 32, h); printf("  pub    %s\n", h);
    hex_enc(sig, 64, h); printf("  sig    %s\n", h);
    hex_enc(d, 32, h);   printf("  digest %s\n", h);
}
// Random 55-char a-z seed -> keys, random digest, stock sign.
static void make_triple(u8 pub[32], u8 sig[64], u8 d[32]) {
    char seed[56]; u8 sub[32], priv[32];
    for (int k = 0; k < 55; k++) seed[k] = (char)('a' + rnd() % 26);
    seed[55] = 0;
    if (!getSubseed((const u8*)seed, sub)) { printf("check_bulk FAILED: getSubseed\n"); exit(1); }
    getPrivateKey(sub, priv);
    getPublicKey(priv, pub);
    rnd_bytes(d, 32);
    sign(sub, pub, d, sig);
}

int main() {
    const char* e = getenv("CHECK_BULK_N");
    int N = e ? atoi(e) : 10000;
    if (N <= 0) { fprintf(stderr, "bad CHECK_BULK_N\n"); return 2; }
    int ok, fail = 0;

    // K12: random len 0..2000; every 1000th iteration a large len 7000..8191.
    ok = 0;
    static u8 in[8192];
    for (int i = 0; i < N; i++) {
        size_t len = (i % 1000 == 0) ? 7000 + rnd() % 1192 : rnd() % 2001;
        rnd_bytes(in, len);
        u8 a[32], b[32];
        KangarooTwelve(in, (unsigned)len, a, 32);
        qubic_k12(in, len, b);
        if (memcmp(a, b, 32) == 0) ok++;
        else printf("check_bulk k12 MISMATCH iter %d len %zu\n", i, len);
    }
    printf("check_bulk_k12: %d/%d ok\n", ok, N);
    fail |= (ok != N);

    // Stock sign -> port verify must accept.
    ok = 0;
    for (int i = 0; i < N; i++) {
        u8 pub[32], sig[64], d[32];
        make_triple(pub, sig, d);
        if (fourq_verify(pub, sig, d) == 1) ok++;
        else printf("check_bulk sign iter %d: port rejects valid sig\n", i);
    }
    printf("check_bulk_sign: %d/%d ok\n", ok, N);
    fail |= (ok != N);

    // Flip one random bit (rotate sig/pub/digest); port must reject, stock must agree.
    ok = 0;
    for (int i = 0; i < N; i++) {
        u8 pub[32], sig[64], d[32];
        make_triple(pub, sig, d);
        int t = i % 3;
        u8* buf = t == 0 ? sig : t == 1 ? pub : d;
        size_t bytes = t == 0 ? 64 : 32;
        buf[rnd() % bytes] ^= (u8)(1u << (rnd() % 8));
        int p = fourq_verify(pub, sig, d);
        int s = verify(pub, d, sig) ? 1 : 0;
        if (p == 0 && s == 0) ok++;
        else {
            printf("check_bulk tamper iter %d target %d: port=%d stock=%d\n", i, t, p, s);
            print_triple(pub, sig, d);
        }
    }
    printf("check_bulk_tamper: %d/%d ok\n", ok, N);
    fail |= (ok != N);

    if (fail) { printf("check_bulk FAILED\n"); return 1; }
    printf("check_bulk OK\n");
    return 0;
}
