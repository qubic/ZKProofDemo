// Sign with the host lib; verify with the port and stock verify(); flipped bytes must fail both.
#include <cstdio>
#include <cstring>
#include "riscv_qubic_crypto.h"
#include "stock_host.h"
#include "tutil.h"
#include "stock_shim.hpp"
#include "stock_patched.cpp"       // stock verify() oracle, separate TU from the lib

static int fails = 0, n = 0;
static void expect(int ok, const char* what, int line) {
    n++; if (!ok) { fails++; printf("*** FAIL (vector %d): %s\n", line, what); }
}

static int both(const uint8_t* pk, const uint8_t* sig, const uint8_t* d, int want, const char* what, int line) {
    int p = fourq_verify(pk, sig, d);
    int s = verify(pk, d, sig) ? 1 : 0;
    char m[128]; snprintf(m, sizeof m, "%s: port=%d stock=%d want=%d", what, p, s, want);
    expect(p == want && s == want, m, line);
    return p == want && s == want;
}

int main(int argc, char** argv) {
    if (argc != 2) { fprintf(stderr, "usage: check_roundtrip <sign_vectors.txt>\n"); return 2; }
    FILE* f = fopen(argv[1], "r"); if (!f) { perror(argv[1]); return 2; }
    char line[512], seed[64], dh[65], sh[129]; int lines = 0;
    while (next_line(f, line, sizeof line)) {
        uint8_t d[32], esig[64], sub[32], priv[32], pub[32], sig[64];
        if (sscanf(line, "%63s %64s %128s", seed, dh, sh) != 3 || !hex_dec(dh, d, 32) || !hex_dec(sh, esig, 64)) { fprintf(stderr, "bad line: %s\n", line); return 2; }
        expect(qubic_seed_to_subseed(seed, sub) == 1, "seed", lines);
        qubic_subseed_to_keys(sub, priv, pub);
        qubic_sign(sub, pub, d, sig);
        expect(memcmp(sig, esig, 64) == 0, "qubic_sign deterministic == vector", lines);
        both(pub, sig, d, 1, "valid sig", lines);
        uint8_t t[64];
        memcpy(t, sig, 64); t[0]  ^= 1; both(pub, t, d, 0, "flip R byte", lines);
        memcpy(t, sig, 64); t[40] ^= 1; both(pub, t, d, 0, "flip S byte", lines);
        memcpy(t, sig, 64); t[63] ^= 0x80; both(pub, t, d, 0, "flip S top bit", lines);
        uint8_t d2[32]; memcpy(d2, d, 32); d2[0] ^= 1; both(pub, sig, d2, 0, "flip digest byte", lines);
        uint8_t p2[32]; memcpy(p2, pub, 32); p2[0] ^= 1; both(p2, sig, d, 0, "flip pubkey byte", lines);
        lines++;
    }
    fclose(f);
    printf("check_roundtrip: %d sign vectors, %d/%d checks passed\n", lines, n - fails, n);
    return (fails || lines == 0) ? 1 : 0;
}
