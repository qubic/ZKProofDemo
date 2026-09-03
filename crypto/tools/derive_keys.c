/* derive_keys <seedfile> — prints "seed pubkeyHex identity" per seed line. */
#include <stdio.h>
#include <string.h>
#include "stock_host.h"

int main(int argc, char** argv) {
    if (argc != 2) { fprintf(stderr, "usage: derive_keys <seedfile>\n"); return 2; }
    FILE* f = fopen(argv[1], "r"); if (!f) { perror(argv[1]); return 2; }
    char line[512]; int ln = 0;
    while (fgets(line, sizeof line, f)) {
        ln++;
        size_t n = strlen(line);
        while (n && (line[n-1] == '\n' || line[n-1] == '\r' || line[n-1] == ' ')) line[--n] = 0;
        if (n == 0 || line[0] == '#') continue;
        uint8_t sub[32], priv[32], pub[32]; char id[61];
        if (n != 55 || !qubic_seed_to_subseed(line, sub)) { fprintf(stderr, "line %d: bad seed\n", ln); return 1; }
        qubic_subseed_to_keys(sub, priv, pub);
        qubic_identity(pub, id, 0);
        printf("%s ", line);
        for (int i = 0; i < 32; i++) printf("%02x", pub[i]);
        printf(" %s\n", id);
    }
    fclose(f);
    return 0;
}
