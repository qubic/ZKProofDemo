/* gen_fixture — writes a ZKQFIX02 oracle fixture (SPEC.md "Wire formats v2"). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "riscv_qubic_crypto.h"
#include "stock_host.h"

#define NUM_COMPUTORS 676
#define PACKET_SIZE   21698
#define TX_HDR        80
#define ITEM_SIZE     72
#define MAX_REPLY     1008

typedef struct { char seed[56]; uint8_t sub[32], priv[32], pub[32]; } key_t_;

static void die(const char* msg) { fprintf(stderr, "gen_fixture: %s\n", msg); exit(1); }

static void put_u16(uint8_t* p, uint16_t v) { p[0] = v & 0xff; p[1] = v >> 8; }
static void put_u32(uint8_t* p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (v >> (8 * i)) & 0xff; }
static void put_u64(uint8_t* p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (v >> (8 * i)) & 0xff; }

static void derive(const char* seed, key_t_* k) {
    if (strlen(seed) != 55 || !qubic_seed_to_subseed(seed, k->sub)) die("bad seed (need 55 a-z chars)");
    memcpy(k->seed, seed, 56);
    qubic_subseed_to_keys(k->sub, k->priv, k->pub);
}

/* Reads non-empty, non-# lines; returns count, at most max. */
static int read_seeds(const char* path, key_t_* out, int max) {
    FILE* f = fopen(path, "r");
    if (!f) { perror(path); exit(1); }
    char line[512]; int n = 0;
    while (fgets(line, sizeof line, f)) {
        size_t len = strlen(line);
        while (len && (line[len-1] == '\n' || line[len-1] == '\r' || line[len-1] == ' ')) line[--len] = 0;
        if (len == 0 || line[0] == '#') continue;
        if (n >= max) { fprintf(stderr, "gen_fixture: %s: more than %d seeds\n", path, max); exit(1); }
        derive(line, &out[n++]);
    }
    fclose(f);
    return n;
}

/* Builds header|input|sig into buf; returns total length. dest = zero. */
static size_t build_tx(uint8_t* buf, const key_t_* signer, int64_t amount, uint32_t tick,
                       uint16_t inputType, const uint8_t* input, uint16_t inputSize) {
    memset(buf, 0, TX_HDR);
    memcpy(buf, signer->pub, 32);
    put_u64(buf + 64, (uint64_t)amount);
    put_u32(buf + 72, tick);
    put_u16(buf + 76, inputType);
    put_u16(buf + 78, inputSize);
    memcpy(buf + TX_HDR, input, inputSize);
    uint8_t d[32];
    qubic_k12(buf, TX_HDR + inputSize, d);
    qubic_sign(signer->sub, signer->pub, d, buf + TX_HDR + inputSize);
    return TX_HDR + inputSize + 64;
}

static int verify_tx(const uint8_t* tx, size_t len) {
    uint8_t d[32];
    qubic_k12(tx, len - 64, d);
    return fourq_verify(tx, tx + len - 64, d);
}

static void fput_u32(FILE* f, uint32_t v) { uint8_t b[4]; put_u32(b, v); fwrite(b, 1, 4, f); }
static void fput_blob(FILE* f, const uint8_t* p, uint32_t len) { fput_u32(f, len); fwrite(p, 1, len, f); }

static const char* USAGE =
"usage: gen_fixture --seeds F --arbitrator-seed F --epoch E --message M --commits N --out F\n"
"  [--user-seed S] [--query-tick T] [--commit-tick T] [--reveal-tick T] [--interface I]\n"
"  [--timeout-ms T] [--bad-commits N] [--wrong-digest N] [--replay-query] [--shuffle] [--reveal-by IDX]\n";

int main(int argc, char** argv) {
    const char *seeds = NULL, *arbSeed = NULL, *message = NULL, *out = NULL;
    char userSeed[56]; memset(userSeed, 'a', 55); userSeed[55] = 0;
    long epoch = -1, commits = -1, badCommits = 0, wrongDigest = 0, revealBy = 0;
    long queryTick = 1000000, commitTick = 1000004, revealTick = 1000007, iface = 0, timeoutMs = 60000;
    int replay = 0, shuffle = 0;

    for (int i = 1; i < argc; i++) {
        const char* a = argv[i];
        if (!strcmp(a, "--replay-query")) { replay = 1; continue; }
        if (!strcmp(a, "--shuffle")) { shuffle = 1; continue; }
        if (i + 1 >= argc) { fprintf(stderr, "%s needs a value\n%s", a, USAGE); return 2; }
        const char* v = argv[++i];
        char* end = NULL; long num = strtol(v, &end, 10);
        int isNum = end && *end == 0 && *v != 0;
        if      (!strcmp(a, "--seeds")) seeds = v;
        else if (!strcmp(a, "--arbitrator-seed")) arbSeed = v;
        else if (!strcmp(a, "--message")) message = v;
        else if (!strcmp(a, "--out")) out = v;
        else if (!strcmp(a, "--user-seed")) { if (strlen(v) != 55) die("--user-seed must be 55 chars"); memcpy(userSeed, v, 56); }
        else if (!isNum || num < 0) { fprintf(stderr, "%s: bad value '%s'\n", a, v); return 2; }
        else if (!strcmp(a, "--epoch")) epoch = num;
        else if (!strcmp(a, "--commits")) commits = num;
        else if (!strcmp(a, "--bad-commits")) badCommits = num;
        else if (!strcmp(a, "--wrong-digest")) wrongDigest = num;
        else if (!strcmp(a, "--reveal-by")) revealBy = num;
        else if (!strcmp(a, "--query-tick")) queryTick = num;
        else if (!strcmp(a, "--commit-tick")) commitTick = num;
        else if (!strcmp(a, "--reveal-tick")) revealTick = num;
        else if (!strcmp(a, "--interface")) iface = num;
        else if (!strcmp(a, "--timeout-ms")) timeoutMs = num;
        else { fprintf(stderr, "unknown argument %s\n%s", a, USAGE); return 2; }
    }
    if (!seeds || !arbSeed || !message || !out || epoch < 0 || commits < 0) { fputs(USAGE, stderr); return 2; }
    if (epoch < 1 || epoch > 65535) die("--epoch must be 1..65535");
    if (commits > NUM_COMPUTORS) die("--commits must be <= 676");
    if (badCommits > commits || wrongDigest > commits) die("--bad-commits/--wrong-digest exceed --commits");
    if (revealBy >= NUM_COMPUTORS) die("--reveal-by must be < 676");
    if (queryTick > 0xffffffffL || commitTick > 0xffffffffL || revealTick > 0xffffffffL) die("tick exceeds u32");
    if (commitTick <= queryTick) die("--commit-tick must be > --query-tick");
    size_t rLen = strlen(message);
    if (rLen < 1 || rLen > MAX_REPLY) die("--message must be 1..1008 bytes");

    static key_t_ comp[NUM_COMPUTORS];
    key_t_ arb, user;
    if (read_seeds(seeds, comp, NUM_COMPUTORS) != NUM_COMPUTORS) die("need exactly 676 computor seeds");
    if (read_seeds(arbSeed, &arb, 1) != 1) die("arbitrator seed file must hold one seed");
    derive(userSeed, &user);

    /* Computors packet: epoch | pubkeys | arbitrator sig over K12(first 21634 B). */
    static uint8_t packet[PACKET_SIZE];
    put_u16(packet, (uint16_t)epoch);
    for (int i = 0; i < NUM_COMPUTORS; i++) memcpy(packet + 2 + 32 * i, comp[i].pub, 32);
    uint8_t d[32];
    qubic_k12(packet, PACKET_SIZE - 64, d);
    qubic_sign(arb.sub, arb.pub, d, packet + PACKET_SIZE - 64);
    if (!fourq_verify(arb.pub, packet + PACKET_SIZE - 64, d)) die("self-check: packet signature invalid");

    /* Query tx (inputType 10). */
    uint64_t queryId = ((uint64_t)queryTick << 31) | 0;
    static uint8_t qInput[8 + MAX_REPLY], queryTx[TX_HDR + 8 + MAX_REPLY + 64];
    put_u32(qInput, (uint32_t)iface);
    put_u32(qInput + 4, (uint32_t)timeoutMs);
    memcpy(qInput + 8, message, rLen);
    size_t qLen = build_tx(queryTx, &user, 1000, (uint32_t)queryTick, 10, qInput, (uint16_t)(8 + rLen));
    if (!verify_tx(queryTx, qLen)) die("self-check: query signature invalid");

    /* Reply digests, right and wrong. */
    static uint8_t reply[MAX_REPLY + 3];
    memcpy(reply, message, rLen);
    uint8_t replyDigest[32], wrongReplyDigest[32];
    qubic_k12(reply, rLen, replyDigest);
    reply[rLen] = 'x';
    qubic_k12(reply, rLen + 1, wrongReplyDigest);

    /* Commit order: file order, or deterministic Fisher-Yates (xorshift64). */
    static int order[NUM_COMPUTORS];
    for (int i = 0; i < NUM_COMPUTORS; i++) order[i] = i;
    if (shuffle) {
        uint64_t x = 0x9e3779b97f4a7c15ULL;
        for (int i = NUM_COMPUTORS - 1; i >= 1; i--) {
            x ^= x << 13; x ^= x >> 7; x ^= x << 17;
            int j = (int)(x % (uint64_t)(i + 1));
            int t = order[i]; order[i] = order[j]; order[j] = t;
        }
    }

    /* Commit txs (inputType 6), one 72-B item each. */
    size_t commitLen = TX_HDR + ITEM_SIZE + 64;
    uint8_t* commitTxs = malloc((size_t)commits * commitLen);
    if (!commitTxs) die("out of memory");
    for (long n = 0; n < commits; n++) {
        int idx = order[n];
        int wrong = n >= commits - wrongDigest, bad = n >= commits - badCommits;
        size_t wl = wrong ? rLen + 1 : rLen;
        uint8_t item[ITEM_SIZE], kp[32];
        put_u16(reply + wl, (uint16_t)idx);
        qubic_k12(reply, wl + 2, kp);
        put_u64(item, queryId + (replay ? 1 : 0));
        memcpy(item + 8, wrong ? wrongReplyDigest : replyDigest, 32);
        memcpy(item + 40, kp, 32);
        uint8_t* tx = commitTxs + (size_t)n * commitLen;
        build_tx(tx, &comp[idx], 0, (uint32_t)commitTick, 6, item, ITEM_SIZE);
        if (bad) tx[commitLen - 64 + 7] ^= 0xff;
        else if (!verify_tx(tx, commitLen)) die("self-check: commit signature invalid");
    }

    /* Reveal tx (inputType 7): queryId | reply. */
    static uint8_t vInput[8 + MAX_REPLY], revealTx[TX_HDR + 8 + MAX_REPLY + 64];
    put_u64(vInput, queryId);
    memcpy(vInput + 8, message, rLen);
    size_t vLen = build_tx(revealTx, &comp[revealBy], 0, (uint32_t)revealTick, 7, vInput, (uint16_t)(8 + rLen));
    if (!verify_tx(revealTx, vLen)) die("self-check: reveal signature invalid");

    FILE* f = fopen(out, "wb");
    if (!f) { perror(out); return 1; }
    fwrite("ZKQFIX02", 1, 8, f);
    fwrite(packet, 1, PACKET_SIZE, f);
    uint8_t q8[8]; put_u64(q8, queryId); fwrite(q8, 1, 8, f);
    fput_blob(f, queryTx, (uint32_t)qLen);
    fput_blob(f, (const uint8_t*)message, (uint32_t)rLen);
    fput_u32(f, (uint32_t)commits);
    for (long n = 0; n < commits; n++) fput_blob(f, commitTxs + (size_t)n * commitLen, (uint32_t)commitLen);
    fput_blob(f, revealTx, (uint32_t)vLen);
    long size = ftell(f);
    if (fclose(f) != 0) { perror(out); return 1; }
    free(commitTxs);

    long overlap = badCommits + wrongDigest > commits ? badCommits + wrongDigest - commits : 0;
    printf("epoch %ld queryId %llu replyDigest ", epoch, (unsigned long long)queryId);
    for (int i = 0; i < 32; i++) printf("%02x", replyDigest[i]);
    printf(" commits %ld (good %ld, bad-sig %ld, wrong-digest %ld, replay %s) -> %s (%ld bytes)\n",
           commits, commits - badCommits - wrongDigest + overlap, badCommits, wrongDigest,
           replay ? "yes" : "no", out, size);
    return 0;
}
