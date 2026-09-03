// SPDX-License-Identifier: LicenseRef-Qubic-Anti-Military
// Origin: reimplements Qubic core platform helpers (src/platform/memory_util.h copyMem/setMem, common_types.h CHAR16).
// Licensed with stock_qubic.c under the Anti-Military License (crypto/LICENSE-QUBIC.md). See NOTICE.

// gcc definitions of the intrinsics and helpers the Qubic reference uses.
#pragma once
#include <immintrin.h>
#include <cstring>

static inline void copyMem(void* dst, const void* src, unsigned long long n) { memcpy(dst, src, (size_t)n); }
static inline void setMem(void* dst, unsigned long long n, int v) { memset(dst, v, (size_t)n); }

// core's platform/common_types.h (used by getIdentity()).
typedef unsigned short CHAR16;

// stock_qubic.c does unaligned `*((__m256i*)p) = ...`; gcc emits aligned vmovdqa and faults.
// Alias __m256i to an aligned(1) vector so accesses become vmovdqu; must come AFTER <immintrin.h>.
typedef long long __m256i_unaligned __attribute__((__vector_size__(32), __may_alias__, aligned(1)));
#define __m256i __m256i_unaligned

static inline unsigned long long _umul128(unsigned long long a, unsigned long long b, unsigned long long* hi) {
    unsigned __int128 p = (unsigned __int128)a * (unsigned __int128)b;
    *hi = (unsigned long long)(p >> 64);
    return (unsigned long long)p;
}
// Returns the 64-bit window starting at bit `shift` of the 128-bit value {High:Low}.
static inline unsigned long long __shiftright128(unsigned long long low, unsigned long long high, unsigned char shift) {
    unsigned __int128 v = ((unsigned __int128)high << 64) | low;
    return (unsigned long long)(v >> (shift & 63));
}
// Returns the high 64 bits of ({High:Low} << shift).
static inline unsigned long long __shiftleft128(unsigned long long low, unsigned long long high, unsigned char shift) {
    unsigned __int128 v = ((unsigned __int128)high << 64) | low;
    return (unsigned long long)((v << (shift & 63)) >> 64);
}
// RDRAND needs -mrdrnd; its randomness is never used (deterministic sign() only), so substitute splitmix64.
static inline int shim_rdrand64_step(unsigned long long* v) {
    static unsigned long long x = 0x9E3779B97F4A7C15ULL;
    x += 0x9E3779B97F4A7C15ULL;
    unsigned long long z = x;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    *v = z ^ (z >> 31);
    return 1;
}
#define _rdrand64_step shim_rdrand64_step
