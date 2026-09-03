/* check_keys — host keygen API vs keygen_vectors.txt + SPEC constants + bad seeds. */
#include <stdio.h>
#include <ctype.h>
#include "stock_host.h"
#include "tutil.h"

#define SEED0      "eraaastggldisjhoojaekgyimrsddjxbvgaawswfvnvaygqmusnkevv"
#define SEED0_ID   "SINUBYSBZKBSVEFQDZBQWUEJWRXCXOZNKPHIXDZWRBKXDSPJEHFAMBACXHUN"
#define SEED0_PUB  "660446bbb36576a689fafe0e70443c64cfe909f31dda1d3a2cf6d46ea2b6f044"
#define ARB_SEED   "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
#define ARB_ID     "ZSDAHLHNHVWTEDYXRTTDWNKGRVPAFQKNTOUXPOXSCDGOPTMUJFWPVATFXHPG"
#define ARB_PUB    "69e68dc170cd9b6dda32b69490f5f71405c5c8d67012e96a86d3ff98ef915ec5"

static int fails = 0, n = 0;

static void expect(int ok, const char* what) {
    n++; if (!ok) { fails++; printf("*** FAIL: %s\n", what); }
}

static void check_seed(const char* seed, const char* pubHex, const char* id) {
    uint8_t sub[32], priv[32], pub[32]; char ph[65], idu[61], idl[61];
    expect(qubic_seed_to_subseed(seed, sub) == 1, "seed accepted");
    qubic_subseed_to_keys(sub, priv, pub);
    hex_enc(pub, 32, ph);
    qubic_identity(pub, idu, 0);
    qubic_identity(pub, idl, 1);
    char msg[256];
    snprintf(msg, sizeof msg, "pubkey %s: got %s want %s", seed, ph, pubHex);
    expect(strcmp(ph, pubHex) == 0, msg);
    snprintf(msg, sizeof msg, "identity %s: got %s want %s", seed, idu, id);
    expect(strcmp(idu, id) == 0, msg);
    int lower_ok = strlen(idl) == 60;
    for (int i = 0; i < 60 && lower_ok; i++) lower_ok = (idl[i] == tolower((unsigned char)idu[i]));
    expect(lower_ok, "lowercase identity");
}

int main(int argc, char** argv) {
    if (argc != 2) { fprintf(stderr, "usage: check_keys <keygen_vectors.txt>\n"); return 2; }

    /* SPEC.md constants (also cross-checked with qubic-cli in run_tests.sh). */
    check_seed(SEED0, SEED0_PUB, SEED0_ID);
    check_seed(ARB_SEED, ARB_PUB, ARB_ID);

    /* Bad seeds must be rejected. */
    uint8_t sub[32];
    char bad1[56]; memcpy(bad1, SEED0, 56); bad1[10] = 'A';
    char bad2[56]; memcpy(bad2, SEED0, 56); bad2[54] = '1';
    expect(qubic_seed_to_subseed(bad1, sub) == 0, "uppercase char rejected");
    expect(qubic_seed_to_subseed(bad2, sub) == 0, "digit rejected");

    /* Every line of keygen_vectors.txt (subseed, priv, pub, identity). */
    FILE* f = fopen(argv[1], "r"); if (!f) { perror(argv[1]); return 2; }
    char line[512], seed[64], sh[65], vh[65], ph[65], id[64]; int lines = 0;
    while (next_line(f, line, sizeof line)) {
        uint8_t esub[32], epriv[32], epub[32], gsub[32], gpriv[32], gpub[32]; char gid[61];
        if (sscanf(line, "%63s %64s %64s %64s %63s", seed, sh, vh, ph, id) != 5 || strlen(seed) != 55 ||
            !hex_dec(sh, esub, 32) || !hex_dec(vh, epriv, 32) || !hex_dec(ph, epub, 32)) { fprintf(stderr, "bad line: %s\n", line); return 2; }
        int ok = qubic_seed_to_subseed(seed, gsub) == 1 && !memcmp(gsub, esub, 32);
        qubic_subseed_to_keys(gsub, gpriv, gpub);
        ok = ok && !memcmp(gpriv, epriv, 32) && !memcmp(gpub, epub, 32);
        qubic_identity(gpub, gid, 0);
        ok = ok && !strcmp(gid, id);
        if (!ok) printf("*** FAIL keygen line %d (%s)\n", lines, seed);
        expect(ok, "keygen vector");
        lines++;
    }
    fclose(f);
    printf("check_keys: %d keygen vectors, %d/%d checks passed\n", lines, n - fails, n);
    return (fails || lines == 0) ? 1 : 0;
}
