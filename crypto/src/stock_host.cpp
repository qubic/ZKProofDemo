/* SPDX-License-Identifier: LicenseRef-Qubic-Anti-Military
 * Includes stock_qubic.c (Qubic core derived) into this TU; licensed with it under the Anti-Military
 * License (crypto/LICENSE-QUBIC.md). See NOTICE. */

/* Host-only helpers over stock_qubic.c, included via the build-generated stock_patched.cpp (__m256i== -> memcmp). */
#include "stock_host.h"
#include "stock_shim.hpp"
#include "stock_patched.cpp"

extern "C" {

int qubic_seed_to_subseed(const char seed[55], uint8_t subseed[32])
{
    return getSubseed((const unsigned char*)seed, subseed) ? 1 : 0;
}

void qubic_subseed_to_keys(const uint8_t subseed[32], uint8_t priv[32], uint8_t pub[32])
{
    unsigned char ss[32];
    memcpy(ss, subseed, 32);          /* getPrivateKey takes non-const */
    getPrivateKey(ss, priv);
    getPublicKey(priv, pub);
}

void qubic_sign(const uint8_t subseed[32], const uint8_t pub[32], const uint8_t digest[32], uint8_t sig[64])
{
    sign(subseed, pub, digest, sig);
}

void qubic_identity(const uint8_t pub[32], char out61[61], int lowerCase)
{
    CHAR16 id[61];
    getIdentity(pub, id, lowerCase != 0);
    for (int i = 0; i < 61; i++) out61[i] = (char)id[i];
}

} /* extern "C" */
