/* check_port — port fourq_verify vs stock-generated schnorrq_vectors.txt. */
#include <stdio.h>
#include <stdlib.h>
#include "riscv_qubic_crypto.h"
#include "tutil.h"

int main(int argc, char** argv) {
    if (argc != 2) { fprintf(stderr, "usage: check_port <schnorrq_vectors.txt>\n"); return 2; }
    FILE* f = fopen(argv[1], "r"); if (!f) { perror(argv[1]); return 2; }
    char line[1024], ph[65], sh[129], dh[65], note[64]; int exp, n = 0, fails = 0;
    while (next_line(f, line, sizeof line)) {
        uint8_t pk[32], sig[64], d[32];
        if (sscanf(line, "%d %64s %128s %64s %63s", &exp, ph, sh, dh, note) != 5 ||
            !hex_dec(ph, pk, 32) || !hex_dec(sh, sig, 64) || !hex_dec(dh, d, 32)) { fprintf(stderr, "bad line: %s\n", line); return 2; }
        int got = fourq_verify(pk, sig, d);
        printf("vec %2d %-22s port=%d expected=%d %s\n", n, note, got, exp, got == exp ? "OK" : "*** MISMATCH ***");
        if (got != exp) fails++;
        n++;
    }
    fclose(f);
    printf("check_port: %d/%d agree with stock_qubic.c verify()\n", n - fails, n);
    return (fails || n == 0) ? 1 : 0;
}
