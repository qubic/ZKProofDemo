/* check_k12 — port qubic_k12 vs stock digests (k12_vectors.txt) + official K12 vectors. */
#include <stdio.h>
#include <stdlib.h>
#include "riscv_qubic_crypto.h"
#include "tutil.h"

/* draft-irtf-cfrg-kangarootwelve: KT128, C = empty, 32-byte output, M = ptn(len). */
static const struct { unsigned len; const char* hex; } OFFICIAL[] = {
    {0,     "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5"},
    {1,     "2bda92450e8b147f8a7cb629e784a058efca7cf7d8218e02d345dfaa65244a1f"},
    {17,    "6bf75fa2239198db4772e36478f8e19b0f371205f6a9a93a273f51df37122888"},
    {289,   "0c315ebcdedbf61426de7dcf8fb725d1e74675d7f5327a5067f367b108ecb67c"},
    {4913,  "cb552e2ec77d9910701d578b457ddf772c12e322e4ee7fe417f92c758f0d59d0"},
    {83521, "8701045e22205345ff4dda05555cbb5c3af1a771c2b89baef37db43d9998b9fe"},
};

int main(int argc, char** argv) {
    if (argc != 2) { fprintf(stderr, "usage: check_k12 <k12_vectors.txt>\n"); return 2; }
    int fails = 0, n = 0;
    FILE* f = fopen(argv[1], "r"); if (!f) { perror(argv[1]); return 2; }
    char line[256], dh[65]; unsigned len;
    while (next_line(f, line, sizeof line)) {
        uint8_t in[701], exp[32], got[32];
        if (sscanf(line, "%u %64s", &len, dh) != 2 || len > 700 || !hex_dec(dh, exp, 32)) { fprintf(stderr, "bad line: %s\n", line); return 2; }
        ptn(in, len);
        qubic_k12(in, len, got);
        if (memcmp(got, exp, 32)) { printf("len %u: *** MISMATCH vs stock ***\n", len); fails++; }
        n++;
    }
    fclose(f);
    printf("check_k12: %d/%d lengths byte-identical to stock_qubic.c K12\n", n - fails, n);

    int on = (int)(sizeof OFFICIAL / sizeof OFFICIAL[0]), ofails = 0;
    uint8_t* buf = malloc(83521);
    for (int i = 0; i < on; i++) {
        uint8_t exp[32], got[32];
        hex_dec(OFFICIAL[i].hex, exp, 32);
        ptn(buf, OFFICIAL[i].len);
        qubic_k12(buf, OFFICIAL[i].len, got);
        int ok = memcmp(got, exp, 32) == 0;
        printf("official K12 ptn(%u): %s\n", OFFICIAL[i].len, ok ? "OK" : "*** MISMATCH ***");
        if (!ok) ofails++;
    }
    free(buf);
    printf("check_k12: %d/%d official KangarooTwelve vectors\n", on - ofails, on);
    return (fails || ofails || n != 701) ? 1 : 0;
}
