/* riscv_qubic_crypto.h — prover C API (see ../SPEC.md "crypto/ C API"). */
#ifndef RISCV_QUBIC_CRYPTO_H
#define RISCV_QUBIC_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* KangarooTwelve, 32-byte output. inLen must be < 2^32. */
void qubic_k12(const uint8_t* in, size_t inLen, uint8_t out32[32]);

/* SchnorrQ verify over a 32-byte digest. Returns 1 = valid, 0 = invalid. */
int fourq_verify(const uint8_t pk[32], const uint8_t sig[64], const uint8_t digest[32]);

#ifdef __cplusplus
}
#endif
#endif /* RISCV_QUBIC_CRYPTO_H */
