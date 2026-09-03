/* stock_host.h — host-only helpers from the Qubic reference (see ../SPEC.md "crypto/ C API"). */
#ifndef STOCK_HOST_H
#define STOCK_HOST_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* seed = 55 lowercase a-z chars. Returns 0 = bad seed, 1 = ok. */
int qubic_seed_to_subseed(const char seed[55], uint8_t subseed[32]);

/* priv = K12(subseed); pub = encode(priv * G). */
void qubic_subseed_to_keys(const uint8_t subseed[32], uint8_t priv[32], uint8_t pub[32]);

/* Deterministic SchnorrQ signature (core's sign()). */
void qubic_sign(const uint8_t subseed[32], const uint8_t pub[32], const uint8_t digest[32], uint8_t sig[64]);

/* 60-char identity + NUL. lowerCase != 0 gives a-z instead of A-Z. */
void qubic_identity(const uint8_t pub[32], char out61[61], int lowerCase);

#ifdef __cplusplus
}
#endif
#endif /* STOCK_HOST_H */
