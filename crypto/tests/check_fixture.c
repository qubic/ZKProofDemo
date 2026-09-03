/* check_fixture <fixture.bin> <arbitratorPubHex> — re-verifies a ZKQFIX02 file like the guest. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "riscv_qubic_crypto.h"

#define NUM_COMPUTORS 676
#define PACKET_SIZE   21698
#define TX_HDR        80
#define QUORUM        451

static const uint8_t* buf; static size_t pos, len;
static void fail(const char* m) { printf("check_fixture: FAIL: %s\n", m); exit(1); }
static const uint8_t* take(size_t n, const char* what) { if (pos + n > len) fail(what); const uint8_t* p = buf + pos; pos += n; return p; }
static uint32_t get_u32(const uint8_t* p) { return p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t get_u64(const uint8_t* p) { return get_u32(p) | (uint64_t)get_u32(p + 4) << 32; }
static const uint8_t* blob(uint32_t* n, const char* what) { *n = get_u32(take(4, what)); return take(*n, what); }
static int zero32(const uint8_t* p) { for (int i = 0; i < 32; i++) if (p[i]) return 0; return 1; }

/* Basic tx checks shared by query/commit/reveal; returns 1 if signature valid. */
static int tx_ok(const uint8_t* tx, uint32_t n, uint16_t type, int64_t amount, int checkAmount) {
    if (n < TX_HDR + 64) return 0;
    uint16_t inputSize = tx[78] | tx[79] << 8, inputType = tx[76] | tx[77] << 8;
    if (TX_HDR + inputSize + 64 != n || inputType != type || !zero32(tx + 32)) return 0;
    if (checkAmount && (int64_t)get_u64(tx + 64) != amount) return 0;
    uint8_t d[32]; qubic_k12(tx, n - 64, d);
    return fourq_verify(tx, tx + n - 64, d);
}
static int computor_index(const uint8_t* packet, const uint8_t* pk) {
    for (int i = 0; i < NUM_COMPUTORS; i++) if (!memcmp(packet + 2 + 32 * i, pk, 32)) return i;
    return -1;
}

int main(int argc, char** argv) {
    if (argc != 3) { fprintf(stderr, "usage: check_fixture <fixture.bin> <arbitratorPubHex>\n"); return 2; }
    uint8_t arb[32];
    if (strlen(argv[2]) != 64) fail("arbitrator pubkey hex must be 64 chars");
    for (int i = 0; i < 32; i++) { unsigned b; if (sscanf(argv[2] + 2 * i, "%2x", &b) != 1) fail("bad hex"); arb[i] = (uint8_t)b; }
    FILE* f = fopen(argv[1], "rb"); if (!f) { perror(argv[1]); return 2; }
    fseek(f, 0, SEEK_END); len = (size_t)ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t* data = malloc(len); if (!data || fread(data, 1, len, f) != len) fail("read");
    fclose(f); buf = data;

    if (memcmp(take(8, "magic"), "ZKQFIX02", 8)) fail("bad magic");
    const uint8_t* packet = take(PACKET_SIZE, "packet");
    uint8_t d[32]; qubic_k12(packet, PACKET_SIZE - 64, d);
    if (!fourq_verify(arb, packet + PACKET_SIZE - 64, d)) fail("packet signature");
    uint32_t epoch = packet[0] | packet[1] << 8;
    if (!epoch) fail("epoch 0");
    for (int i = 0; i < NUM_COMPUTORS; i++)
        for (int j = i + 1; j < NUM_COMPUTORS; j++)
            if (!memcmp(packet + 2 + 32 * i, packet + 2 + 32 * j, 32)) fail("repeated pubkey");

    uint64_t queryId = get_u64(take(8, "queryId"));
    uint32_t qLen, rLen, n, vLen;
    const uint8_t* queryTx = blob(&qLen, "queryTx");
    if (!tx_ok(queryTx, qLen, 10, 0, 0)) fail("query tx");
    uint32_t queryTick = get_u32(queryTx + 72);
    if (queryTick != (uint32_t)(queryId >> 31)) fail("query tick != queryId >> 31");
    const uint8_t* reply = blob(&rLen, "reply");
    if (rLen < 1 || rLen > 1008) fail("reply length");
    uint8_t replyDigest[32]; qubic_k12(reply, rLen, replyDigest);

    n = get_u32(take(4, "n"));
    static uint8_t seen[NUM_COMPUTORS];
    uint8_t* kpBuf = malloc(rLen + 2); memcpy(kpBuf, reply, rLen);
    uint32_t counted = 0;
    for (uint32_t c = 0; c < n; c++) {
        uint32_t cl; const uint8_t* tx = blob(&cl, "commitTx");
        if (!tx_ok(tx, cl, 6, 0, 1) || get_u32(tx + 72) <= queryTick) continue;
        int idx = computor_index(packet, tx);
        if (idx < 0 || seen[idx]) continue;
        uint8_t kp[32]; kpBuf[rLen] = idx & 0xff; kpBuf[rLen + 1] = idx >> 8;
        qubic_k12(kpBuf, rLen + 2, kp);
        uint16_t inputSize = tx[78] | tx[79] << 8;
        int hit = 0;
        for (uint32_t off = 0; off + 72 <= inputSize; off += 72) {
            const uint8_t* it = tx + TX_HDR + off;
            if (get_u64(it) == queryId && !memcmp(it + 8, replyDigest, 32) && !memcmp(it + 40, kp, 32)) hit = 1;
        }
        if (hit) { seen[idx] = 1; counted++; }
    }
    const uint8_t* revealTx = blob(&vLen, "revealTx");
    if (!tx_ok(revealTx, vLen, 7, 0, 1) || computor_index(packet, revealTx) < 0) fail("reveal tx");
    if (vLen != TX_HDR + 8 + rLen + 64 || get_u64(revealTx + TX_HDR) != queryId ||
        memcmp(revealTx + TX_HDR + 8, reply, rLen)) fail("reveal input != queryId | reply");
    if (pos != len) fail("trailing bytes");

    printf("check_fixture: epoch %u queryId %llu commits %u valid %u (quorum %d) size %zu\n",
           epoch, (unsigned long long)queryId, n, counted, QUORUM, len);
    if (counted != n) fail("some commits invalid");
    if (counted < QUORUM) fail("quorum not reached");
    printf("fixture OK\n");
    return 0;
}
