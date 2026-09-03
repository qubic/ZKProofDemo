/* SPDX-License-Identifier: LicenseRef-Qubic-Anti-Military
 * Origin: portable port of Qubic core src/four_q.h + src/kangaroo_twelve.h (https://github.com/qubic/core),
 * Anti-Military License (crypto/LICENSE-QUBIC.md). FourQ/SchnorrQ derives from MSR FourQlib (MIT,
 * crypto/LICENSE-FourQlib.md); KangarooTwelve derives from XKCP (CC0 / public domain). See NOTICE. */

/* Portable rv32im port of SchnorrQ (FourQ) verify: C11 + uint64_t only; needs riscv_tables.c. */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "riscv_qubic_crypto.h" /* prototype guard for the guest FFI */

typedef int bool_t;
#define TRUE  1
#define FALSE 0

/* ===================== portable primitive helpers ===================== */

static inline void copyMem(void *dst, const void *src, unsigned long long n) { memcpy(dst, src, (size_t)n); }
static inline void setMem(void *dst, unsigned long long n, int v) { memset(dst, v, (size_t)n); }

/* 64-bit rotate left */
static inline uint64_t ROL64(uint64_t a, unsigned offset) {
    return (offset == 0) ? a : ((a << offset) ^ (a >> (64 - offset)));
}

/* andnot: ~a & b */
static inline uint64_t andn64(uint64_t a, uint64_t b) { return (~a) & b; }

/* 64x64 -> 128 multiply, returns low 64, *hi gets high 64. No __int128. */
static inline uint64_t umul128(uint64_t a, uint64_t b, uint64_t *hi) {
    uint64_t a_lo = (uint32_t)a, a_hi = a >> 32;
    uint64_t b_lo = (uint32_t)b, b_hi = b >> 32;

    uint64_t p_ll = a_lo * b_lo;
    uint64_t p_lh = a_lo * b_hi;
    uint64_t p_hl = a_hi * b_lo;
    uint64_t p_hh = a_hi * b_hi;

    uint64_t mid = (p_ll >> 32) + (uint32_t)p_lh + (uint32_t)p_hl;
    uint64_t lo  = (p_ll & 0xFFFFFFFFULL) | (mid << 32);
    *hi = p_hh + (p_lh >> 32) + (p_hl >> 32) + (mid >> 32);
    return lo;
}

/* add with carry-in, returns carry-out */
static inline unsigned char addcarry64(unsigned char cin, uint64_t a, uint64_t b, uint64_t *out) {
    uint64_t t = a + cin;
    uint64_t s = t + b;
    *out = s;
    return (unsigned char)((t < a) | (s < t));
}

/* sub with borrow-in, returns borrow-out */
static inline unsigned char subborrow64(unsigned char bin, uint64_t a, uint64_t b, uint64_t *out) {
    uint64_t t = a - b;
    uint64_t s = t - bin;
    *out = s;
    return (unsigned char)((a < b) | (t < bin));
}

/* funnel shift right: (hi:lo) >> n, return low 64 bits. n in [0,63] */
static inline uint64_t shiftright128(uint64_t lo, uint64_t hi, unsigned n) {
    if (n == 0) return lo;
    return (lo >> n) | (hi << (64 - n));
}

/* funnel shift left: (hi:lo) << n, return high 64 bits. n in [0,63] */
static inline uint64_t shiftleft128(uint64_t lo, uint64_t hi, unsigned n) {
    if (n == 0) return hi;
    return (hi << n) | (lo >> (64 - n));
}

/* ===================== KangarooTwelve (generic scalar) ===================== */

#define KeccakF1600RoundConstant0   0x000000008000808bULL
#define KeccakF1600RoundConstant1   0x800000000000008bULL
#define KeccakF1600RoundConstant2   0x8000000000008089ULL
#define KeccakF1600RoundConstant3   0x8000000000008003ULL
#define KeccakF1600RoundConstant4   0x8000000000008002ULL
#define KeccakF1600RoundConstant5   0x8000000000000080ULL
#define KeccakF1600RoundConstant6   0x000000000000800aULL
#define KeccakF1600RoundConstant7   0x800000008000000aULL
#define KeccakF1600RoundConstant8   0x8000000080008081ULL
#define KeccakF1600RoundConstant9   0x8000000000008080ULL
#define KeccakF1600RoundConstant10  0x0000000080000001ULL

#define declareABCDE \
    uint64_t Aba, Abe, Abi, Abo, Abu; \
    uint64_t Aga, Age, Agi, Ago, Agu; \
    uint64_t Aka, Ake, Aki, Ako, Aku; \
    uint64_t Ama, Ame, Ami, Amo, Amu; \
    uint64_t Asa, Ase, Asi, Aso, Asu; \
    uint64_t Bba, Bbe, Bbi, Bbo, Bbu; \
    uint64_t Bga, Bge, Bgi, Bgo, Bgu; \
    uint64_t Bka, Bke, Bki, Bko, Bku; \
    uint64_t Bma, Bme, Bmi, Bmo, Bmu; \
    uint64_t Bsa, Bse, Bsi, Bso, Bsu; \
    uint64_t Ca, Ce, Ci, Co, Cu; \
    uint64_t Da, De, Di, Do, Du; \
    uint64_t Eba, Ebe, Ebi, Ebo, Ebu; \
    uint64_t Ega, Ege, Egi, Ego, Egu; \
    uint64_t Eka, Eke, Eki, Eko, Eku; \
    uint64_t Ema, Eme, Emi, Emo, Emu; \
    uint64_t Esa, Ese, Esi, Eso, Esu;

#define thetaRhoPiChiIotaPrepareTheta(i, A, E) \
    Da = Cu^ROL64(Ce, 1); \
    De = Ca^ROL64(Ci, 1); \
    Di = Ce^ROL64(Co, 1); \
    Do = Ci^ROL64(Cu, 1); \
    Du = Co^ROL64(Ca, 1); \
    A##ba ^= Da; Bba = A##ba; \
    A##ge ^= De; Bbe = ROL64(A##ge, 44); \
    A##ki ^= Di; Bbi = ROL64(A##ki, 43); \
    A##mo ^= Do; Bbo = ROL64(A##mo, 21); \
    A##su ^= Du; Bbu = ROL64(A##su, 14); \
    E##ba = Bba ^ andn64(Bbe, Bbi); E##ba ^= KeccakF1600RoundConstant##i; Ca = E##ba; \
    E##be = Bbe ^ andn64(Bbi, Bbo); Ce = E##be; \
    E##bi = Bbi ^ andn64(Bbo, Bbu); Ci = E##bi; \
    E##bo = Bbo ^ andn64(Bbu, Bba); Co = E##bo; \
    E##bu = Bbu ^ andn64(Bba, Bbe); Cu = E##bu; \
    A##bo ^= Do; Bga = ROL64(A##bo, 28); \
    A##gu ^= Du; Bge = ROL64(A##gu, 20); \
    A##ka ^= Da; Bgi = ROL64(A##ka, 3); \
    A##me ^= De; Bgo = ROL64(A##me, 45); \
    A##si ^= Di; Bgu = ROL64(A##si, 61); \
    E##ga = Bga ^ andn64(Bge, Bgi); Ca ^= E##ga; \
    E##ge = Bge ^ andn64(Bgi, Bgo); Ce ^= E##ge; \
    E##gi = Bgi ^ andn64(Bgo, Bgu); Ci ^= E##gi; \
    E##go = Bgo ^ andn64(Bgu, Bga); Co ^= E##go; \
    E##gu = Bgu ^ andn64(Bga, Bge); Cu ^= E##gu; \
    A##be ^= De; Bka = ROL64(A##be, 1); \
    A##gi ^= Di; Bke = ROL64(A##gi, 6); \
    A##ko ^= Do; Bki = ROL64(A##ko, 25); \
    A##mu ^= Du; Bko = ROL64(A##mu, 8); \
    A##sa ^= Da; Bku = ROL64(A##sa, 18); \
    E##ka = Bka ^ andn64(Bke, Bki); Ca ^= E##ka; \
    E##ke = Bke ^ andn64(Bki, Bko); Ce ^= E##ke; \
    E##ki = Bki ^ andn64(Bko, Bku); Ci ^= E##ki; \
    E##ko = Bko ^ andn64(Bku, Bka); Co ^= E##ko; \
    E##ku = Bku ^ andn64(Bka, Bke); Cu ^= E##ku; \
    A##bu ^= Du; Bma = ROL64(A##bu, 27); \
    A##ga ^= Da; Bme = ROL64(A##ga, 36); \
    A##ke ^= De; Bmi = ROL64(A##ke, 10); \
    A##mi ^= Di; Bmo = ROL64(A##mi, 15); \
    A##so ^= Do; Bmu = ROL64(A##so, 56); \
    E##ma = Bma ^ andn64(Bme, Bmi); Ca ^= E##ma; \
    E##me = Bme ^ andn64(Bmi, Bmo); Ce ^= E##me; \
    E##mi = Bmi ^ andn64(Bmo, Bmu); Ci ^= E##mi; \
    E##mo = Bmo ^ andn64(Bmu, Bma); Co ^= E##mo; \
    E##mu = Bmu ^ andn64(Bma, Bme); Cu ^= E##mu; \
    A##bi ^= Di; Bsa = ROL64(A##bi, 62); \
    A##go ^= Do; Bse = ROL64(A##go, 55); \
    A##ku ^= Du; Bsi = ROL64(A##ku, 39); \
    A##ma ^= Da; Bso = ROL64(A##ma, 41); \
    A##se ^= De; Bsu = ROL64(A##se, 2); \
    E##sa = Bsa ^ andn64(Bse, Bsi); Ca ^= E##sa; \
    E##se = Bse ^ andn64(Bsi, Bso); Ce ^= E##se; \
    E##si = Bsi ^ andn64(Bso, Bsu); Ci ^= E##si; \
    E##so = Bso ^ andn64(Bsu, Bsa); Co ^= E##so; \
    E##su = Bsu ^ andn64(Bsa, Bse); Cu ^= E##su;

#define copyFromState(state) \
    Aba = state[ 0]; Abe = state[ 1]; Abi = state[ 2]; Abo = state[ 3]; Abu = state[ 4]; \
    Aga = state[ 5]; Age = state[ 6]; Agi = state[ 7]; Ago = state[ 8]; Agu = state[ 9]; \
    Aka = state[10]; Ake = state[11]; Aki = state[12]; Ako = state[13]; Aku = state[14]; \
    Ama = state[15]; Ame = state[16]; Ami = state[17]; Amo = state[18]; Amu = state[19]; \
    Asa = state[20]; Ase = state[21]; Asi = state[22]; Aso = state[23]; Asu = state[24];

#define copyToState(state) \
    state[ 0] = Aba; state[ 1] = Abe; state[ 2] = Abi; state[ 3] = Abo; state[ 4] = Abu; \
    state[ 5] = Aga; state[ 6] = Age; state[ 7] = Agi; state[ 8] = Ago; state[ 9] = Agu; \
    state[10] = Aka; state[11] = Ake; state[12] = Aki; state[13] = Ako; state[14] = Aku; \
    state[15] = Ama; state[16] = Ame; state[17] = Ami; state[18] = Amo; state[19] = Amu; \
    state[20] = Asa; state[21] = Ase; state[22] = Asi; state[23] = Aso; state[24] = Asu;

#define rounds12 \
    Ca = Aba^Aga^Aka^Ama^Asa; \
    Ce = Abe^Age^Ake^Ame^Ase; \
    Ci = Abi^Agi^Aki^Ami^Asi; \
    Co = Abo^Ago^Ako^Amo^Aso; \
    Cu = Abu^Agu^Aku^Amu^Asu; \
    thetaRhoPiChiIotaPrepareTheta(0, A, E) \
    thetaRhoPiChiIotaPrepareTheta(1, E, A) \
    thetaRhoPiChiIotaPrepareTheta(2, A, E) \
    thetaRhoPiChiIotaPrepareTheta(3, E, A) \
    thetaRhoPiChiIotaPrepareTheta(4, A, E) \
    thetaRhoPiChiIotaPrepareTheta(5, E, A) \
    thetaRhoPiChiIotaPrepareTheta(6, A, E) \
    thetaRhoPiChiIotaPrepareTheta(7, E, A) \
    thetaRhoPiChiIotaPrepareTheta(8, A, E) \
    thetaRhoPiChiIotaPrepareTheta(9, E, A) \
    thetaRhoPiChiIotaPrepareTheta(10, A, E) \
    Da = Cu^ROL64(Ce, 1); De = Ca^ROL64(Ci, 1); Di = Ce^ROL64(Co, 1); \
    Do = Ci^ROL64(Cu, 1); Du = Co^ROL64(Ca, 1); \
    Eba ^= Da; Bba = Eba; \
    Ege ^= De; Bbe = ROL64(Ege, 44); \
    Eki ^= Di; Bbi = ROL64(Eki, 43); \
    Emo ^= Do; Bbo = ROL64(Emo, 21); \
    Esu ^= Du; Bbu = ROL64(Esu, 14); \
    Aba = Bba ^ andn64(Bbe, Bbi); Aba ^= 0x8000000080008008ULL; \
    Abe = Bbe ^ andn64(Bbi, Bbo); Abi = Bbi ^ andn64(Bbo, Bbu); \
    Abo = Bbo ^ andn64(Bbu, Bba); Abu = Bbu ^ andn64(Bba, Bbe); \
    Ebo ^= Do; Bga = ROL64(Ebo, 28); \
    Egu ^= Du; Bge = ROL64(Egu, 20); \
    Eka ^= Da; Bgi = ROL64(Eka, 3); \
    Eme ^= De; Bgo = ROL64(Eme, 45); \
    Esi ^= Di; Bgu = ROL64(Esi, 61); \
    Aga = Bga ^ andn64(Bge, Bgi); Age = Bge ^ andn64(Bgi, Bgo); \
    Agi = Bgi ^ andn64(Bgo, Bgu); Ago = Bgo ^ andn64(Bgu, Bga); Agu = Bgu ^ andn64(Bga, Bge); \
    Ebe ^= De; Bka = ROL64(Ebe, 1); \
    Egi ^= Di; Bke = ROL64(Egi, 6); \
    Eko ^= Do; Bki = ROL64(Eko, 25); \
    Emu ^= Du; Bko = ROL64(Emu, 8); \
    Esa ^= Da; Bku = ROL64(Esa, 18); \
    Aka = Bka ^ andn64(Bke, Bki); Ake = Bke ^ andn64(Bki, Bko); \
    Aki = Bki ^ andn64(Bko, Bku); Ako = Bko ^ andn64(Bku, Bka); Aku = Bku ^ andn64(Bka, Bke); \
    Ebu ^= Du; Bma = ROL64(Ebu, 27); \
    Ega ^= Da; Bme = ROL64(Ega, 36); \
    Eke ^= De; Bmi = ROL64(Eke, 10); \
    Emi ^= Di; Bmo = ROL64(Emi, 15); \
    Eso ^= Do; Bmu = ROL64(Eso, 56); \
    Ama = Bma ^ andn64(Bme, Bmi); Ame = Bme ^ andn64(Bmi, Bmo); \
    Ami = Bmi ^ andn64(Bmo, Bmu); Amo = Bmo ^ andn64(Bmu, Bma); Amu = Bmu ^ andn64(Bma, Bme); \
    Ebi ^= Di; Bsa = ROL64(Ebi, 62); \
    Ego ^= Do; Bse = ROL64(Ego, 55); \
    Eku ^= Du; Bsi = ROL64(Eku, 39); \
    Ema ^= Da; Bso = ROL64(Ema, 41); \
    Ese ^= De; Bsu = ROL64(Ese, 2); \
    Asa = Bsa ^ andn64(Bse, Bsi); Ase = Bse ^ andn64(Bsi, Bso); \
    Asi = Bsi ^ andn64(Bso, Bsu); Aso = Bso ^ andn64(Bsu, Bsa); Asu = Bsu ^ andn64(Bsa, Bse);

#define K12_security        128
#define K12_capacity        (2 * K12_security)
#define K12_capacityInBytes (K12_capacity / 8)
#define K12_rateInBytes     ((1600 - K12_capacity) / 8)   /* 168 */
#define K12_chunkSize       8192
#define K12_suffixLeaf      0x0B

typedef struct {
    /* 8-byte aligned: read as uint64_t lanes; unaligned rv32im access silently corrupts the hash. */
    unsigned char state[200] __attribute__((aligned(8)));
    unsigned char byteIOIndex;
} KangarooTwelve_F;

static void KeccakP1600_Permute_12rounds(unsigned char* state) {
    declareABCDE
    uint64_t* s = (uint64_t*)state;
    copyFromState(s)
    rounds12
    copyToState(s)
}

static void KangarooTwelve_F_Absorb(KangarooTwelve_F* instance, const unsigned char* data, unsigned long long dataByteLen) {
    unsigned long long i = 0;
    while (i < dataByteLen) {
        if (!instance->byteIOIndex && dataByteLen >= i + K12_rateInBytes) {
            declareABCDE
            uint64_t* stateAsLanes = (uint64_t*)instance->state;
            copyFromState(stateAsLanes)
            unsigned long long modifiedDataByteLen = dataByteLen - i;
            while (modifiedDataByteLen >= K12_rateInBytes) {
                uint64_t d[21];
                copyMem(d, data, 21 * sizeof(uint64_t)); /* alignment-safe load of 168 bytes */
                Aba ^= d[0];  Abe ^= d[1];  Abi ^= d[2];  Abo ^= d[3];  Abu ^= d[4];
                Aga ^= d[5];  Age ^= d[6];  Agi ^= d[7];  Ago ^= d[8];  Agu ^= d[9];
                Aka ^= d[10]; Ake ^= d[11]; Aki ^= d[12]; Ako ^= d[13]; Aku ^= d[14];
                Ama ^= d[15]; Ame ^= d[16]; Ami ^= d[17]; Amo ^= d[18]; Amu ^= d[19];
                Asa ^= d[20];
                rounds12
                data += K12_rateInBytes;
                modifiedDataByteLen -= K12_rateInBytes;
            }
            copyToState(stateAsLanes)
            i = dataByteLen - modifiedDataByteLen;
        } else {
            unsigned char partialBlock;
            if ((dataByteLen - i) + instance->byteIOIndex > K12_rateInBytes)
                partialBlock = K12_rateInBytes - instance->byteIOIndex;
            else
                partialBlock = (unsigned char)(dataByteLen - i);
            i += partialBlock;

            if (!instance->byteIOIndex) {
                unsigned int j = 0;
                for (; (j + 1) <= (unsigned int)(partialBlock >> 3); j += 1) {
                    uint64_t lane;
                    copyMem(&lane, data + j * 8, 8);
                    ((uint64_t*)instance->state)[j] ^= lane;
                }
                if (partialBlock & 7) {
                    uint64_t lane = 0;
                    copyMem(&lane, data + (partialBlock & 0xFFFFFFF8), partialBlock & 7);
                    ((uint64_t*)instance->state)[partialBlock >> 3] ^= lane;
                }
            } else {
                unsigned int _sizeLeft = partialBlock;
                unsigned int _lanePosition = instance->byteIOIndex >> 3;
                unsigned int _offsetInLane = instance->byteIOIndex & 7;
                const unsigned char* _curData = data;
                while (_sizeLeft > 0) {
                    unsigned int _bytesInLane = 8 - _offsetInLane;
                    if (_bytesInLane > _sizeLeft) _bytesInLane = _sizeLeft;
                    if (_bytesInLane) {
                        uint64_t lane = 0;
                        copyMem(&lane, (void*)_curData, _bytesInLane);
                        ((uint64_t*)instance->state)[_lanePosition] ^= (lane << (_offsetInLane << 3));
                    }
                    _sizeLeft -= _bytesInLane;
                    _lanePosition++;
                    _offsetInLane = 0;
                    _curData += _bytesInLane;
                }
            }
            data += partialBlock;
            instance->byteIOIndex += partialBlock;
            if (instance->byteIOIndex == K12_rateInBytes) {
                KeccakP1600_Permute_12rounds(instance->state);
                instance->byteIOIndex = 0;
            }
        }
    }
}

static void KangarooTwelve(const unsigned char* input, unsigned int inputByteLen,
                           unsigned char* output, unsigned int outputByteLen) {
    KangarooTwelve_F queueNode;
    KangarooTwelve_F finalNode;
    unsigned int blockNumber, queueAbsorbedLen;

    setMem(&finalNode, sizeof(KangarooTwelve_F), 0);
    const unsigned int len = inputByteLen ^ ((K12_chunkSize ^ inputByteLen) & -(unsigned)(K12_chunkSize < inputByteLen));
    KangarooTwelve_F_Absorb(&finalNode, input, len);
    input += len;
    inputByteLen -= len;
    if (len == K12_chunkSize && inputByteLen) {
        blockNumber = 1;
        queueAbsorbedLen = 0;
        finalNode.state[finalNode.byteIOIndex] ^= 0x03;
        if (++finalNode.byteIOIndex == K12_rateInBytes) {
            KeccakP1600_Permute_12rounds(finalNode.state);
            finalNode.byteIOIndex = 0;
        } else {
            finalNode.byteIOIndex = (finalNode.byteIOIndex + 7) & ~7;
        }
        while (inputByteLen > 0) {
            const unsigned int clen = K12_chunkSize ^ ((inputByteLen ^ K12_chunkSize) & -(unsigned)(inputByteLen < K12_chunkSize));
            setMem(&queueNode, sizeof(KangarooTwelve_F), 0);
            KangarooTwelve_F_Absorb(&queueNode, input, clen);
            input += clen;
            inputByteLen -= clen;
            if (clen == K12_chunkSize) {
                ++blockNumber;
                queueNode.state[queueNode.byteIOIndex] ^= K12_suffixLeaf;
                queueNode.state[K12_rateInBytes - 1] ^= 0x80;
                KeccakP1600_Permute_12rounds(queueNode.state);
                queueNode.byteIOIndex = K12_capacityInBytes;
                KangarooTwelve_F_Absorb(&finalNode, queueNode.state, K12_capacityInBytes);
            } else {
                queueAbsorbedLen = clen;
            }
        }
        if (queueAbsorbedLen) {
            if (++queueNode.byteIOIndex == K12_rateInBytes) {
                KeccakP1600_Permute_12rounds(queueNode.state);
                queueNode.byteIOIndex = 0;
            }
            if (++queueAbsorbedLen == K12_chunkSize) {
                ++blockNumber;
                queueAbsorbedLen = 0;
                queueNode.state[queueNode.byteIOIndex] ^= K12_suffixLeaf;
                queueNode.state[K12_rateInBytes - 1] ^= 0x80;
                KeccakP1600_Permute_12rounds(queueNode.state);
                queueNode.byteIOIndex = K12_capacityInBytes;
                KangarooTwelve_F_Absorb(&finalNode, queueNode.state, K12_capacityInBytes);
            }
        } else {
            setMem(queueNode.state, sizeof(queueNode.state), 0);
            queueNode.byteIOIndex = 1;
            queueAbsorbedLen = 1;
        }
    } else {
        if (len == K12_chunkSize) {
            blockNumber = 1;
            finalNode.state[finalNode.byteIOIndex] ^= 0x03;
            if (++finalNode.byteIOIndex == K12_rateInBytes) {
                KeccakP1600_Permute_12rounds(finalNode.state);
                finalNode.byteIOIndex = 0;
            } else {
                finalNode.byteIOIndex = (finalNode.byteIOIndex + 7) & ~7;
            }
            setMem(queueNode.state, sizeof(queueNode.state), 0);
            queueNode.byteIOIndex = 1;
            queueAbsorbedLen = 1;
        } else {
            blockNumber = 0;
            if (++finalNode.byteIOIndex == K12_rateInBytes) {
                KeccakP1600_Permute_12rounds(finalNode.state);
                finalNode.state[0] ^= 0x07;
            } else {
                finalNode.state[finalNode.byteIOIndex] ^= 0x07;
            }
        }
    }

    if (blockNumber) {
        if (queueAbsorbedLen) {
            blockNumber++;
            queueNode.state[queueNode.byteIOIndex] ^= K12_suffixLeaf;
            queueNode.state[K12_rateInBytes - 1] ^= 0x80;
            KeccakP1600_Permute_12rounds(queueNode.state);
            KangarooTwelve_F_Absorb(&finalNode, queueNode.state, K12_capacityInBytes);
        }
        unsigned int n = 0;
        for (unsigned long long v = --blockNumber; v && (n < sizeof(unsigned long long)); ++n, v >>= 8) {}
        unsigned char encbuf[sizeof(unsigned long long) + 1 + 2];
        for (unsigned int j = 1; j <= n; ++j)
            encbuf[j - 1] = (unsigned char)(blockNumber >> (8 * (n - j)));
        encbuf[n] = (unsigned char)n;
        encbuf[++n] = 0xFF;
        encbuf[++n] = 0xFF;
        KangarooTwelve_F_Absorb(&finalNode, encbuf, ++n);
        finalNode.state[finalNode.byteIOIndex] ^= 0x06;
    }
    finalNode.state[K12_rateInBytes - 1] ^= 0x80;
    KeccakP1600_Permute_12rounds(finalNode.state);
    copyMem(output, finalNode.state, outputByteLen);
}

/* ===================== FourQ field arithmetic ===================== */

#define CURVE_ORDER_0 0x2FB2540EC7768CE7ULL
#define CURVE_ORDER_1 0xDFBD004DFE0F7999ULL
#define CURVE_ORDER_2 0xF05397829CBC14E5ULL
#define CURVE_ORDER_3 0x0029CBC14E5E0A72ULL
#define MONTGOMERY_SMALL_R_PRIME_0 0xE12FE5F079BC3929ULL
#define MONTGOMERY_SMALL_R_PRIME_1 0xD75E78B8D1FCDCF3ULL
#define MONTGOMERY_SMALL_R_PRIME_2 0xBCE409ED76B5DB21ULL
#define MONTGOMERY_SMALL_R_PRIME_3 0xF32702FDAFC1C074ULL

#define B11 0xF6F900D81F5F5E6AULL
#define B12 0x1363E862C22A2DA0ULL
#define B13 0xF8BD9FCE1337FCF1ULL
#define B14 0x084F739986B9E651ULL
#define B21 0xE2B6A4157B033D2CULL
#define B22 0x0000000000000001ULL
#define B23 0xFFFFFFFFFFFFFFFFULL
#define B24 0xDA243A43722E9830ULL
#define B31 0xE85452E2DCE0FCFEULL
#define B32 0xFD3BDEE51C7725AFULL
#define B33 0x2E4D21C98927C49FULL
#define B34 0xF56190BB3FD13269ULL
#define B41 0xEC91CBF56EF737C1ULL
#define B42 0xCEDD20D23C1F00CEULL
#define B43 0x068A49F02AA8A9B5ULL
#define B44 0x18D5087896DE0AEAULL
#define C1 0x72482C5251A4559CULL
#define C2 0x59F95B0ADD276F6CULL
#define C3 0x7DD2D17C4625FA78ULL
#define C4 0x6BC57DEF56CE8877ULL

typedef uint64_t felm_t[2];
typedef felm_t f2elm_t[2];

typedef struct { f2elm_t x; f2elm_t y; } point_affine;
typedef point_affine point_t[1];

typedef struct { f2elm_t x; f2elm_t y; f2elm_t z; f2elm_t ta; f2elm_t tb; } point_extproj;
typedef point_extproj point_extproj_t[1];

typedef struct { f2elm_t xy; f2elm_t yx; f2elm_t z2; f2elm_t t2; } point_extproj_precomp;
typedef point_extproj_precomp point_extproj_precomp_t[1];

typedef struct { f2elm_t xy; f2elm_t yx; f2elm_t t2; } point_precomp;
typedef point_precomp point_precomp_t[1];

static const uint64_t PARAMETER_d[4] = { 0x0000000000000142ULL, 0x00000000000000E4ULL, 0xB3821488F1FC0C8DULL, 0x5E472F846657E0FCULL };
static const uint64_t curve_order[4] = { CURVE_ORDER_0, CURVE_ORDER_1, CURVE_ORDER_2, CURVE_ORDER_3 };
static const uint64_t Montgomery_Rprime[4] = { 0xC81DB8795FF3D621ULL, 0x173EA5AAEA6B387DULL, 0x3D01B7C72136F61CULL, 0x0006A5F16AC8F9D3ULL };
static const uint64_t ONE[4] = { 1, 0, 0, 0 };

static const uint64_t ctau1[4]     = { 0x74DCD57CEBCE74C3ULL, 0x1964DE2C3AFAD20CULL, 0x12, 0x0C };
static const uint64_t ctaudual1[4] = { 0x9ECAA6D9DECDF034ULL, 0x4AA740EB23058652ULL, 0x11, 0x7FFFFFFFFFFFFFF4ULL };
static const uint64_t cphi0[4] = { 0xFFFFFFFFFFFFFFF7ULL, 0x05, 0x4F65536CEF66F81AULL, 0x2553A0759182C329ULL };
static const uint64_t cphi1[4] = { 0x07, 0x05, 0x334D90E9E28296F9ULL, 0x62C8CAA0C50C62CFULL };
static const uint64_t cphi2[4] = { 0x15, 0x0F, 0x2C2CB7154F1DF391ULL, 0x78DF262B6C9B5C98ULL };
static const uint64_t cphi3[4] = { 0x03, 0x02, 0x92440457A7962EA4ULL, 0x5084C6491D76342AULL };
static const uint64_t cphi4[4] = { 0x03, 0x03, 0xA1098C923AEC6855ULL, 0x12440457A7962EA4ULL };
static const uint64_t cphi5[4] = { 0x0F, 0x0A, 0x669B21D3C5052DF3ULL, 0x459195418A18C59EULL };
static const uint64_t cphi6[4] = { 0x18, 0x12, 0xCD3643A78A0A5BE7ULL, 0x0B232A8314318B3CULL };
static const uint64_t cphi7[4] = { 0x23, 0x18, 0x66C183035F48781AULL, 0x3963BC1C99E2EA1AULL };
static const uint64_t cphi8[4] = { 0xF0, 0xAA, 0x44E251582B5D0EF0ULL, 0x1F529F860316CBE5ULL };
static const uint64_t cphi9[4] = { 0xBEF, 0x870, 0x14D3E48976E2505ULL, 0xFD52E9CFE00375BULL };
static const uint64_t cpsi1[4] = { 0xEDF07F4767E346EFULL, 0x2AF99E9A83D54A02ULL, 0x13A, 0xDE };
static const uint64_t cpsi2[4] = { 0x143, 0xE4, 0x4C7DEB770E03F372ULL, 0x21B8D07B99A81F03ULL };
static const uint64_t cpsi3[4] = { 0x09, 0x06, 0x3A6E6ABE75E73A61ULL, 0x4CB26F161D7D6906ULL };
static const uint64_t cpsi4[4] = { 0xFFFFFFFFFFFFFFF6ULL, 0x7FFFFFFFFFFFFFF9ULL, 0xC59195418A18C59EULL, 0x334D90E9E28296F9ULL };

static const uint64_t ell1[4] = { 0x259686E09D1A7D4FULL, 0xF75682ACE6A6BD66ULL, 0xFC5BB5C5EA2BE5DFULL, 0x07 };
static const uint64_t ell2[4] = { 0xD1BA1D84DD627AFBULL, 0x2BD235580F468D8DULL, 0x8FD4B04CAA6C0F8AULL, 0x03 };
static const uint64_t ell3[4] = { 0x9B291A33678C203CULL, 0xC42BD6C965DCA902ULL, 0xD038BF8D0BFFBAF6ULL, 0x00 };
static const uint64_t ell4[4] = { 0x12E5666B77E7FDC0ULL, 0x81CBDC3714983D82ULL, 0x1B073877A22D8410ULL, 0x03 };

extern const uint64_t FIXED_BASE_TABLE[960];
extern const uint64_t DOUBLE_SCALAR_TABLE[3072];

#if defined(ZKQ_BIGINT2)
/* RISC Zero bigint2 shims (methods/guest/src/bigint2.rs); results fully reduced (< p). */
extern void zkq_fpmul1271(const uint64_t* a, const uint64_t* b, uint64_t* c);
extern void zkq_fp2mul1271(const uint64_t* a, const uint64_t* b, uint64_t* c);
extern void zkq_fpinv1271(const uint64_t* a, uint64_t* c);
#endif

static void mod1271(felm_t a) {
    unsigned char b;
    b = subborrow64(0, a[0], 0xFFFFFFFFFFFFFFFFULL, &a[0]);
    subborrow64(b, a[1], 0x7FFFFFFFFFFFFFFFULL, &a[1]);
    uint64_t mask = 0 - (a[1] >> 63);
    b = addcarry64(0, a[0], mask, &a[0]);
    addcarry64(b, a[1], 0x7FFFFFFFFFFFFFFFULL & mask, &a[1]);
}

static void fpadd1271(felm_t a, felm_t b, felm_t c) {
    unsigned char cc;
    cc = addcarry64(0, a[0], b[0], &c[0]);
    addcarry64(cc, a[1], b[1], &c[1]);
    cc = addcarry64(0, c[0], c[1] >> 63, &c[0]);
    addcarry64(cc, c[1] & 0x7FFFFFFFFFFFFFFFULL, 0, &c[1]);
}

static void fpsub1271(felm_t a, felm_t b, felm_t c) {
    unsigned char bb;
    bb = subborrow64(0, a[0], b[0], &c[0]);
    subborrow64(bb, a[1], b[1], &c[1]);
    bb = subborrow64(0, c[0], c[1] >> 63, &c[0]);
    subborrow64(bb, c[1] & 0x7FFFFFFFFFFFFFFFULL, 0, &c[1]);
}

static void fpneg1271(felm_t a) {
    a[0] = ~a[0];
    a[1] = 0x7FFFFFFFFFFFFFFFULL - a[1];
}

static void fpmul1271(felm_t a, felm_t b, felm_t c) {
#if defined(ZKQ_BIGINT2)
    zkq_fpmul1271(a, b, c);
#else
    uint64_t tt1[2], tt2[2], tt3[2];
    unsigned char cc;
    tt1[0] = umul128(a[0], b[0], &tt3[0]);
    tt2[0] = umul128(a[0], b[1], &tt2[1]);
    cc = addcarry64(0, tt2[0], tt3[0], &tt2[0]); addcarry64(cc, tt2[1], 0, &tt2[1]);
    tt3[0] = umul128(a[1], b[0], &tt3[1]);
    cc = addcarry64(0, tt2[0], tt3[0], &tt2[0]); addcarry64(cc, tt2[1], tt3[1], &tt2[1]);
    tt3[0] = umul128(a[1], b[1], &tt3[1]);
    tt3[1] = shiftleft128(tt3[0], tt3[1], 1);
    cc = addcarry64(0, shiftright128(tt2[0], tt2[1], 63), tt3[0] << 1, &tt3[0]);
    addcarry64(cc, tt2[1] >> 63, tt3[1], &tt3[1]);
    cc = addcarry64(0, tt1[0], tt3[0], &tt1[0]);
    addcarry64(cc, tt2[0] & 0x7FFFFFFFFFFFFFFFULL, tt3[1], &tt1[1]);
    cc = addcarry64(0, tt1[0], tt1[1] >> 63, &c[0]);
    addcarry64(cc, tt1[1] & 0x7FFFFFFFFFFFFFFFULL, 0, &c[1]);
#endif
}

static void fpsqr1271(felm_t a, felm_t c) {
#if defined(ZKQ_BIGINT2)
    zkq_fpmul1271(a, a, c);
#else
    uint64_t tt1[2], tt2[2], tt3[2];
    unsigned char cc;
    tt1[0] = umul128(a[0], a[0], &tt3[0]);
    tt2[0] = umul128(a[0], a[1], &tt2[1]);
    cc = addcarry64(0, tt2[0], tt3[0], &tt3[0]); addcarry64(cc, tt2[1], 0, &tt3[1]);
    cc = addcarry64(0, tt2[0], tt3[0], &tt2[0]); addcarry64(cc, tt2[1], tt3[1], &tt2[1]);
    tt3[0] = umul128(a[1], a[1], &tt3[1]);
    tt3[1] = shiftleft128(tt3[0], tt3[1], 1);
    cc = addcarry64(0, shiftright128(tt2[0], tt2[1], 63), tt3[0] << 1, &tt3[0]);
    addcarry64(cc, tt2[1] >> 63, tt3[1], &tt3[1]);
    cc = addcarry64(0, tt1[0], tt3[0], &tt1[0]);
    addcarry64(cc, tt2[0] & 0x7FFFFFFFFFFFFFFFULL, tt3[1], &tt1[1]);
    cc = addcarry64(0, tt1[0], tt1[1] >> 63, &c[0]);
    addcarry64(cc, tt1[1] & 0x7FFFFFFFFFFFFFFFULL, 0, &c[1]);
#endif
}

static void fpexp1251(felm_t a, felm_t af) {
    felm_t t1, t2, t3, t4, t5;
    fpsqr1271(a, t2); fpmul1271(a, t2, t2);
    fpsqr1271(t2, t3); fpsqr1271(t3, t3); fpmul1271(t2, t3, t3);
    fpsqr1271(t3, t4); fpsqr1271(t4, t4); fpsqr1271(t4, t4); fpsqr1271(t4, t4); fpmul1271(t3, t4, t4);
    fpsqr1271(t4, t5); for (unsigned i = 0; i < 7; i++) fpsqr1271(t5, t5); fpmul1271(t4, t5, t5);
    fpsqr1271(t5, t2); for (unsigned i = 0; i < 15; i++) fpsqr1271(t2, t2); fpmul1271(t5, t2, t2);
    fpsqr1271(t2, t1); for (unsigned i = 0; i < 31; i++) fpsqr1271(t1, t1); fpmul1271(t2, t1, t1);
    for (unsigned i = 0; i < 32; i++) fpsqr1271(t1, t1); fpmul1271(t1, t2, t1);
    for (unsigned i = 0; i < 16; i++) fpsqr1271(t1, t1); fpmul1271(t5, t1, t1);
    for (unsigned i = 0; i < 8; i++) fpsqr1271(t1, t1); fpmul1271(t4, t1, t1);
    for (unsigned i = 0; i < 4; i++) fpsqr1271(t1, t1); fpmul1271(t3, t1, t1);
    fpsqr1271(t1, t1); fpmul1271(a, t1, af);
}

static inline void f2copy(f2elm_t d, const f2elm_t s) {
    d[0][0] = s[0][0]; d[0][1] = s[0][1]; d[1][0] = s[1][0]; d[1][1] = s[1][1];
}

static void fp2div1271(f2elm_t a) {
    uint64_t mask, temp[2];
    unsigned char cc;
    mask = (0 - (1 & a[0][0]));
    cc = addcarry64(0, a[0][0], mask, &temp[0]); addcarry64(cc, a[0][1], (mask >> 1), &temp[1]);
    a[0][0] = shiftright128(temp[0], temp[1], 1); a[0][1] = (temp[1] >> 1);
    mask = (0 - (1 & a[1][0]));
    cc = addcarry64(0, a[1][0], mask, &temp[0]); addcarry64(cc, a[1][1], (mask >> 1), &temp[1]);
    a[1][0] = shiftright128(temp[0], temp[1], 1); a[1][1] = (temp[1] >> 1);
}

static void fp2neg1271(f2elm_t a) { fpneg1271(a[0]); fpneg1271(a[1]); }

static void fp2sqr1271(f2elm_t a, f2elm_t c) {
#if defined(ZKQ_BIGINT2)
    zkq_fp2mul1271((const uint64_t*)a, (const uint64_t*)a, (uint64_t*)c);
#else
    felm_t t1, t2, t3;
    fpadd1271(a[0], a[1], t1);
    fpsub1271(a[0], a[1], t2);
    fpmul1271(a[0], a[1], t3);
    fpmul1271(t1, t2, c[0]);
    fpadd1271(t3, t3, c[1]);
#endif
}

static void fp2mul1271(f2elm_t a, f2elm_t b, f2elm_t c) {
#if defined(ZKQ_BIGINT2)
    zkq_fp2mul1271((const uint64_t*)a, (const uint64_t*)b, (uint64_t*)c);
#else
    felm_t t1, t2, t3, t4;
    fpmul1271(a[0], b[0], t1);
    fpmul1271(a[1], b[1], t2);
    fpadd1271(a[0], a[1], t3);
    fpadd1271(b[0], b[1], t4);
    fpsub1271(t1, t2, c[0]);
    fpmul1271(t3, t4, t3);
    fpsub1271(t3, t1, t3);
    fpsub1271(t3, t2, c[1]);
#endif
}

/* c = a^(p-2) = a^-1 mod p; a == 0 mod p gives 0, exactly like the exponentiation. */
static void fpinv1271(felm_t a, felm_t c) {
#if defined(ZKQ_BIGINT2)
    felm_t t = { a[0], a[1] };
    mod1271(t);
    if (!t[0] && !t[1]) { c[0] = 0; c[1] = 0; return; }
    zkq_fpinv1271(t, c);
#else
    felm_t t;
    fpexp1251(a, t);
    fpsqr1271(t, t);
    fpsqr1271(t, t);
    fpmul1271(a, t, c);
#endif
}

static void fp2add1271(f2elm_t a, f2elm_t b, f2elm_t c) { fpadd1271(a[0], b[0], c[0]); fpadd1271(a[1], b[1], c[1]); }
static void fp2sub1271(f2elm_t a, f2elm_t b, f2elm_t c) { fpsub1271(a[0], b[0], c[0]); fpsub1271(a[1], b[1], c[1]); }
static void fp2addsub1271(f2elm_t a, f2elm_t b, f2elm_t c) { fp2add1271(a, a, a); fp2sub1271(a, b, c); }

/* ===================== FourQ group ops ===================== */

static void table_lookup_fixed_base(point_precomp_t P, unsigned int digit, unsigned int sign) {
    const point_precomp_t* tbl = (const point_precomp_t*)FIXED_BASE_TABLE;
    if (sign) {
        f2copy(P->xy, tbl[digit]->yx);
        f2copy(P->yx, tbl[digit]->xy);
        P->t2[0][0] = ~(tbl[digit]->t2[0][0]);
        P->t2[0][1] = 0x7FFFFFFFFFFFFFFFULL - tbl[digit]->t2[0][1];
        P->t2[1][0] = ~(tbl[digit]->t2[1][0]);
        P->t2[1][1] = 0x7FFFFFFFFFFFFFFFULL - tbl[digit]->t2[1][1];
    } else {
        f2copy(P->xy, tbl[digit]->xy);
        f2copy(P->yx, tbl[digit]->yx);
        f2copy(P->t2, tbl[digit]->t2);
    }
}

static void multiply(const uint64_t* a, const uint64_t* b, uint64_t* c) {
    uint64_t r[8] = {0,0,0,0,0,0,0,0};
    for (int i = 0; i < 4; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 4; j++) {
            uint64_t hi, lo = umul128(a[i], b[j], &hi);
            uint64_t s;
            unsigned char c1 = addcarry64(0, r[i + j], lo, &s);
            unsigned char c2 = addcarry64(0, s, carry, &r[i + j]);
            carry = hi + c1 + c2;
        }
        r[i + 4] += carry;
    }
    for (int k = 0; k < 8; k++) c[k] = r[k];
}

static void Montgomery_multiply_mod_order(const uint64_t* ma, const uint64_t* mb, uint64_t* mc) {
    uint64_t P[8], Q[4], temp[8];
    unsigned char cc;

    if (mb[0] == 1 && !mb[1] && !mb[2] && !mb[3]) {
        P[0]=ma[0]; P[1]=ma[1]; P[2]=ma[2]; P[3]=ma[3];
        P[4]=P[5]=P[6]=P[7]=0;
    } else {
        multiply(ma, mb, P);
    }

    {
        const uint64_t rp[4] = { MONTGOMERY_SMALL_R_PRIME_0, MONTGOMERY_SMALL_R_PRIME_1,
                                 MONTGOMERY_SMALL_R_PRIME_2, MONTGOMERY_SMALL_R_PRIME_3 };
        uint64_t r[4] = {0,0,0,0};
        for (int i = 0; i < 4; i++) {
            uint64_t carry = 0;
            for (int j = 0; i + j < 4; j++) {
                uint64_t hi, lo = umul128(P[i], rp[j], &hi);
                uint64_t t;
                unsigned char c1 = addcarry64(0, r[i + j], lo, &t);
                unsigned char c2 = addcarry64(0, t, carry, &r[i + j]);
                carry = hi + c1 + c2;
            }
        }
        Q[0]=r[0]; Q[1]=r[1]; Q[2]=r[2]; Q[3]=r[3];
    }

    multiply(Q, curve_order, temp);

    unsigned char add_carry = 0;
    add_carry = addcarry64(add_carry, P[0], temp[0], &temp[0]);
    add_carry = addcarry64(add_carry, P[1], temp[1], &temp[1]);
    add_carry = addcarry64(add_carry, P[2], temp[2], &temp[2]);
    add_carry = addcarry64(add_carry, P[3], temp[3], &temp[3]);
    add_carry = addcarry64(add_carry, P[4], temp[4], &temp[4]);
    add_carry = addcarry64(add_carry, P[5], temp[5], &temp[5]);
    add_carry = addcarry64(add_carry, P[6], temp[6], &temp[6]);
    add_carry = addcarry64(add_carry, P[7], temp[7], &temp[7]);

    unsigned char borrow = 0;
    borrow = subborrow64(borrow, temp[4], CURVE_ORDER_0, &mc[0]);
    borrow = subborrow64(borrow, temp[5], CURVE_ORDER_1, &mc[1]);
    borrow = subborrow64(borrow, temp[6], CURVE_ORDER_2, &mc[2]);
    borrow = subborrow64(borrow, temp[7], CURVE_ORDER_3, &mc[3]);

    if ((unsigned char)(add_carry - borrow)) {
        cc = addcarry64(0, mc[0], CURVE_ORDER_0, &mc[0]);
        cc = addcarry64(cc, mc[1], CURVE_ORDER_1, &mc[1]);
        cc = addcarry64(cc, mc[2], CURVE_ORDER_2, &mc[2]);
        addcarry64(cc, mc[3], CURVE_ORDER_3, &mc[3]);
    }
}

static void eccnorm(point_extproj_t P, point_t Q) {
    f2elm_t t1;
    fpsqr1271(P->z[0], t1[0]);
    fpsqr1271(P->z[1], t1[1]);
    fpadd1271(t1[0], t1[1], t1[0]);
    fpinv1271(t1[0], t1[0]);
    fpneg1271(P->z[1]);
    fpmul1271(P->z[0], t1[0], P->z[0]);
    fpmul1271(P->z[1], t1[0], P->z[1]);
    fp2mul1271(P->x, P->z, Q->x);
    fp2mul1271(P->y, P->z, Q->y);
    mod1271(Q->x[0]); mod1271(Q->x[1]); mod1271(Q->y[0]); mod1271(Q->y[1]);
}

static void R1_to_R2(point_extproj_t P, point_extproj_precomp_t Q) {
    fp2add1271(P->ta, P->ta, Q->t2);
    fp2add1271(P->x, P->y, Q->xy);
    fp2sub1271(P->y, P->x, Q->yx);
    fp2mul1271(Q->t2, P->tb, Q->t2);
    fp2add1271(P->z, P->z, Q->z2);
    fp2mul1271(Q->t2, (felm_t*)&PARAMETER_d, Q->t2);
}

static void R1_to_R3(point_extproj_t P, point_extproj_precomp_t Q) {
    fp2add1271(P->x, P->y, Q->xy);
    fp2sub1271(P->y, P->x, Q->yx);
    fp2mul1271(P->ta, P->tb, Q->t2);
    f2copy(Q->z2, P->z);
}

static void R2_to_R4(point_extproj_precomp_t P, point_extproj_t Q) {
    fp2sub1271(P->xy, P->yx, Q->x);
    fp2add1271(P->xy, P->yx, Q->y);
    f2copy(Q->z, P->z2);
}

static void eccdouble(point_extproj_t P) {
    f2elm_t t1, t2;
    fp2sqr1271(P->x, t1);
    fp2sqr1271(P->y, t2);
    fp2add1271(P->x, P->y, P->x);
    fp2add1271(t1, t2, P->tb);
    fp2sub1271(t2, t1, t1);
    fp2sqr1271(P->x, P->ta);
    fp2sqr1271(P->z, t2);
    fp2sub1271(P->ta, P->tb, P->ta);
    fp2addsub1271(t2, t1, t2);
    fp2mul1271(t1, P->tb, P->y);
    fp2mul1271(t2, P->ta, P->x);
    fp2mul1271(t1, t2, P->z);
}

static void eccadd_core(point_extproj_precomp_t P, point_extproj_precomp_t Q, point_extproj_t R) {
    f2elm_t t1, t2;
    fp2mul1271(P->t2, Q->t2, R->z);
    fp2mul1271(P->z2, Q->z2, t1);
    fp2mul1271(P->xy, Q->xy, R->x);
    fp2mul1271(P->yx, Q->yx, R->y);
    fp2sub1271(t1, R->z, t2);
    fp2add1271(t1, R->z, t1);
    fp2sub1271(R->x, R->y, R->tb);
    fp2add1271(R->x, R->y, R->ta);
    fp2mul1271(R->tb, t2, R->x);
    fp2mul1271(t1, t2, R->z);
    fp2mul1271(R->ta, t1, R->y);
}

static void eccadd(point_extproj_precomp_t Q, point_extproj_t P) {
    point_extproj_precomp_t R;
    R1_to_R3(P, R);
    eccadd_core(Q, R, P);
}

static void point_setup(point_t P, point_extproj_t Q) {
    f2copy(Q->x, P->x);
    f2copy(Q->y, P->y);
    f2copy(Q->ta, P->x);
    f2copy(Q->tb, P->y);
    Q->z[0][0] = 1; Q->z[0][1] = 0; Q->z[1][0] = 0; Q->z[1][1] = 0;
}

static bool_t ecc_point_validate(point_extproj_t P) {
    f2elm_t t1, t2, t3;
    fp2sqr1271(P->y, t1);
    fp2sqr1271(P->x, t2);
    fp2sub1271(t1, t2, t3);
    fp2mul1271(t1, t2, t1);
    fp2mul1271(t1, (felm_t*)&PARAMETER_d, t2);
    t1[0][0] = 1; t1[0][1] = 0; t1[1][0] = 0; t1[1][1] = 0;
    fp2add1271(t2, t1, t2);
    fp2sub1271(t3, t2, t1);
    return ((!(t1[0][0] | t1[0][1]) || !((t1[0][0] + 1) | (t1[0][1] + 1)))
         && (!(t1[1][0] | t1[1][1]) || !((t1[1][0] + 1) | (t1[1][1] + 1))));
}

static void eccmadd(point_precomp_t Q, point_extproj_t P) {
    f2elm_t t1, t2;
    fp2mul1271(P->ta, P->tb, P->ta);
    fp2add1271(P->z, P->z, t1);
    fp2mul1271(P->ta, Q->t2, P->ta);
    fp2add1271(P->x, P->y, P->z);
    fp2sub1271(P->y, P->x, P->tb);
    fp2sub1271(t1, P->ta, t2);
    fp2add1271(t1, P->ta, t1);
    fp2mul1271(Q->xy, P->z, P->ta);
    fp2mul1271(Q->yx, P->tb, P->x);
    fp2mul1271(t1, t2, P->z);
    fp2sub1271(P->ta, P->x, P->tb);
    fp2add1271(P->ta, P->x, P->ta);
    fp2mul1271(P->tb, t2, P->x);
    fp2mul1271(P->ta, t1, P->y);
}

static void ecc_tau(point_extproj_t P) {
    f2elm_t t0, t1;
    fp2sqr1271(P->x, t0);
    fp2sqr1271(P->y, t1);
    fp2mul1271(P->x, P->y, P->x);
    fp2sqr1271(P->z, P->y);
    fp2add1271(t0, t1, P->z);
    fp2sub1271(t1, t0, t0);
    fp2add1271(P->y, P->y, P->y);
    fp2mul1271(P->x, t0, P->x);
    fp2sub1271(P->y, t0, P->y);
    fp2mul1271(P->x, (felm_t*)&ctau1, P->x);
    fp2mul1271(P->y, P->z, P->y);
    fp2mul1271(P->z, t0, P->z);
}

static void ecc_tau_dual(point_extproj_t P) {
    f2elm_t t0, t1;
    fp2sqr1271(P->x, t0);
    fp2sqr1271(P->z, P->ta);
    fp2sqr1271(P->y, t1);
    fp2add1271(P->ta, P->ta, P->z);
    fp2sub1271(t1, t0, P->ta);
    fp2add1271(t0, t1, t0);
    fp2mul1271(P->x, P->y, P->x);
    fp2sub1271(P->z, P->ta, P->z);
    fp2mul1271(P->x, (felm_t*)&ctaudual1, P->tb);
    fp2mul1271(P->z, P->ta, P->y);
    fp2mul1271(P->tb, t0, P->x);
    fp2mul1271(P->z, t0, P->z);
}

static void ecc_delphidel(point_extproj_t P) {
    f2elm_t t0, t1, t2, t3, t4, t5, t6;
    fp2sqr1271(P->z, t4);
    fp2mul1271(P->y, P->z, t3);
    fp2mul1271(t4, (felm_t*)&cphi4, t0);
    fp2sqr1271(P->y, t2);
    fp2add1271(t0, t2, t0);
    fp2mul1271(t3, (felm_t*)&cphi3, t1);
    fp2sub1271(t0, t1, t5);
    fp2add1271(t0, t1, t0);
    fp2mul1271(t0, P->z, t0);
    fp2mul1271(t3, (felm_t*)&cphi1, t1);
    fp2mul1271(t0, t5, t0);
    fp2mul1271(t4, (felm_t*)&cphi2, t5);
    fp2add1271(t2, t5, t5);
    fp2sub1271(t1, t5, t6);
    fp2add1271(t1, t5, t1);
    fp2mul1271(t6, t1, t6);
    fp2mul1271(t6, (felm_t*)&cphi0, t6);
    fp2mul1271(P->x, t6, P->x);
    fp2sqr1271(t2, t6);
    fp2sqr1271(t3, t2);
    fp2sqr1271(t4, t3);
    fp2mul1271(t2, (felm_t*)&cphi8, t1);
    fp2mul1271(t3, (felm_t*)&cphi9, t5);
    fp2add1271(t1, t6, t1);
    fp2mul1271(t2, (felm_t*)&cphi6, t2);
    fp2mul1271(t3, (felm_t*)&cphi7, t3);
    fp2add1271(t1, t5, t1);
    fp2add1271(t2, t3, t2);
    fp2mul1271(t1, P->y, t1);
    fp2add1271(t6, t2, P->y);
    fp2mul1271(P->x, t1, P->x);
    fp2mul1271(P->y, (felm_t*)&cphi5, P->y);
    fpneg1271(P->x[1]);
    fp2mul1271(P->y, P->z, P->y);
    fp2mul1271(t0, t1, P->z);
    fp2mul1271(P->y, t0, P->y);
    fpneg1271(P->z[1]);
    fpneg1271(P->y[1]);
}

static void ecc_delpsidel(point_extproj_t P) {
    f2elm_t t0, t1, t2;
    fpneg1271(P->x[1]);
    fpneg1271(P->z[1]);
    fpneg1271(P->y[1]);
    fp2sqr1271(P->z, t2);
    fp2sqr1271(P->x, t0);
    fp2mul1271(P->x, t2, P->x);
    fp2mul1271(t2, (felm_t*)&cpsi2, P->z);
    fp2mul1271(t2, (felm_t*)&cpsi3, t1);
    fp2mul1271(t2, (felm_t*)&cpsi4, t2);
    fp2add1271(t0, P->z, P->z);
    fp2add1271(t0, t2, t2);
    fp2add1271(t0, t1, t1);
    fp2neg1271(t2);
    fp2mul1271(P->z, P->y, P->z);
    fp2mul1271(P->x, t2, P->x);
    fp2mul1271(t1, P->z, P->y);
    fp2mul1271(P->x, (felm_t*)&cpsi1, P->x);
    fp2mul1271(P->z, t2, P->z);
}

static void ecc_psi(point_extproj_t P) { ecc_tau(P); ecc_delpsidel(P); ecc_tau_dual(P); }
static void ecc_phi(point_extproj_t P) { ecc_tau(P); ecc_delphidel(P); ecc_tau_dual(P); }

static void eccneg_extproj_precomp(point_extproj_precomp_t P, point_extproj_precomp_t Q) {
    f2copy(Q->t2, P->t2);
    f2copy(Q->yx, P->xy);
    f2copy(Q->xy, P->yx);
    f2copy(Q->z2, P->z2);
    fp2neg1271(Q->t2);
}

static void eccneg_precomp(point_precomp_t P, point_precomp_t Q) {
    f2copy(Q->t2, P->t2);
    f2copy(Q->yx, P->xy);
    f2copy(Q->xy, P->yx);
    fp2neg1271(Q->t2);
}

static uint64_t mul_truncate(uint64_t* s, uint64_t* C) {
    uint64_t prod[8] = {0,0,0,0,0,0,0,0};
    for (int i = 0; i < 4; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 4; j++) {
            uint64_t hi, lo = umul128(s[i], C[j], &hi);
            uint64_t t;
            unsigned char c1 = addcarry64(0, prod[i + j], lo, &t);
            unsigned char c2 = addcarry64(0, t, carry, &prod[i + j]);
            carry = hi + c1 + c2;
        }
        prod[i + 4] += carry;
    }
    return prod[4];
}

static void decompose(uint64_t* k, uint64_t* scalars) {
    const uint64_t a1 = mul_truncate(k, (uint64_t*)ell1);
    const uint64_t a2 = mul_truncate(k, (uint64_t*)ell2);
    const uint64_t a3 = mul_truncate(k, (uint64_t*)ell3);
    const uint64_t a4 = mul_truncate(k, (uint64_t*)ell4);

    scalars[0] = a1 * B11 + a2 * B21 + a3 * B31 + a4 * B41 + C1 + k[0];
    scalars[1] = a1 * B12 + a2 * B22 + a3 * B32 + a4 * B42 + C2;
    scalars[2] = a1 * B13 + a2 * B23 + a3 * B33 + a4 * B43 + C3;
    scalars[3] = a1 * B14 + a2 * B24 + a3 * B34 + a4 * B44 + C4;
    if (!(scalars[0] & 1)) {
        scalars[0] -= B41;
        scalars[1] -= B42;
        scalars[2] -= B43;
        scalars[3] -= B44;
    }
}

static void wNAF_recode(uint64_t scalar, unsigned int w, signed char* digits) {
    const int val1 = (int)(1 << (w - 1)) - 1;
    const int val2 = (int)(1 << w);
    const uint64_t mask = (uint64_t)val2 - 1;
    int index = 0;
    while (scalar) {
        int digit = (int)(scalar & 1);
        if (!digit) {
            scalar >>= 1;
            digits[index] = 0;
        } else {
            digit = (int)(scalar & mask);
            scalar >>= w;
            if (digit > val1) digit -= val2;
            if (digit < 0) scalar++;
            digits[index] = (char)digit;
            if (scalar) {
                for (unsigned int i = 0; i < (w - 1); i++) digits[++index] = 0;
            }
        }
        index++;
    }
    setMem(&digits[index], 65 - index, 0);
}

static void ecc_precomp_double(point_extproj_t P, point_extproj_precomp_t* Table) {
    point_extproj_t Q;
    point_extproj_precomp_t PP;
    R1_to_R2(P, Table[0]);
    eccdouble(P);
    R1_to_R3(P, PP);
    eccadd_core(Table[0], PP, Q); R1_to_R2(Q, Table[1]);
    eccadd_core(Table[1], PP, Q); R1_to_R2(Q, Table[2]);
    eccadd_core(Table[2], PP, Q); R1_to_R2(Q, Table[3]);
}

static bool_t ecc_mul_double(uint64_t* k, uint64_t* l, point_t Q) {
    /* wNAF digits are signed; RISC-V gcc's unsigned char would index tables out of bounds (-fsigned-char). */
    signed char digits_k1[65], digits_k2[65], digits_k3[65], digits_k4[65];
    signed char digits_l1[65], digits_l2[65], digits_l3[65], digits_l4[65];
    point_precomp_t V;
    point_extproj_t Q1, Q2, Q3, Q4, T;
    point_extproj_precomp_t U, Q_table1[4], Q_table2[4], Q_table3[4], Q_table4[4];
    uint64_t k_scalars[4], l_scalars[4];
    const point_precomp_t* DST = (const point_precomp_t*)DOUBLE_SCALAR_TABLE;

    point_setup(Q, Q1);
    if (!ecc_point_validate(Q1)) return FALSE;

    f2copy(Q2->x, Q1->x); f2copy(Q2->y, Q1->y); f2copy(Q2->z, Q1->z);
    f2copy(Q2->ta, Q1->ta); f2copy(Q2->tb, Q1->tb);
    ecc_phi(Q2);
    f2copy(Q3->x, Q1->x); f2copy(Q3->y, Q1->y); f2copy(Q3->z, Q1->z);
    f2copy(Q3->ta, Q1->ta); f2copy(Q3->tb, Q1->tb);
    ecc_psi(Q3);
    f2copy(Q4->x, Q2->x); f2copy(Q4->y, Q2->y); f2copy(Q4->z, Q2->z);
    f2copy(Q4->ta, Q2->ta); f2copy(Q4->tb, Q2->tb);
    ecc_psi(Q4);

    decompose(k, k_scalars);
    decompose(l, l_scalars);
    wNAF_recode(k_scalars[0], 8, digits_k1);
    wNAF_recode(k_scalars[1], 8, digits_k2);
    wNAF_recode(k_scalars[2], 8, digits_k3);
    wNAF_recode(k_scalars[3], 8, digits_k4);
    wNAF_recode(l_scalars[0], 4, digits_l1);
    wNAF_recode(l_scalars[1], 4, digits_l2);
    wNAF_recode(l_scalars[2], 4, digits_l3);
    wNAF_recode(l_scalars[3], 4, digits_l4);
    ecc_precomp_double(Q1, Q_table1);
    ecc_precomp_double(Q2, Q_table2);
    ecc_precomp_double(Q3, Q_table3);
    ecc_precomp_double(Q4, Q_table4);

    T->x[0][0]=0; T->x[0][1]=0; T->x[1][0]=0; T->x[1][1]=0;
    T->y[0][0]=1; T->y[0][1]=0; T->y[1][0]=0; T->y[1][1]=0;
    T->z[0][0]=1; T->z[0][1]=0; T->z[1][0]=0; T->z[1][1]=0;

    for (unsigned int i = 65; i--; ) {
        eccdouble(T);

        if (digits_l1[i] < 0) { eccneg_extproj_precomp(Q_table1[(-digits_l1[i]) >> 1], U); eccadd(U, T); }
        else if (digits_l1[i] > 0) { eccadd(Q_table1[(digits_l1[i]) >> 1], T); }
        if (digits_l2[i] < 0) { eccneg_extproj_precomp(Q_table2[(-digits_l2[i]) >> 1], U); eccadd(U, T); }
        else if (digits_l2[i] > 0) { eccadd(Q_table2[(digits_l2[i]) >> 1], T); }
        if (digits_l3[i] < 0) { eccneg_extproj_precomp(Q_table3[(-digits_l3[i]) >> 1], U); eccadd(U, T); }
        else if (digits_l3[i] > 0) { eccadd(Q_table3[(digits_l3[i]) >> 1], T); }
        if (digits_l4[i] < 0) { eccneg_extproj_precomp(Q_table4[(-digits_l4[i]) >> 1], U); eccadd(U, T); }
        else if (digits_l4[i] > 0) { eccadd(Q_table4[(digits_l4[i]) >> 1], T); }

        if (digits_k1[i] < 0) { eccneg_precomp((point_precomp*)DST[(-digits_k1[i]) >> 1], V); eccmadd(V, T); }
        else if (digits_k1[i] > 0) { eccmadd((point_precomp*)DST[(digits_k1[i]) >> 1], T); }
        if (digits_k2[i] < 0) { eccneg_precomp((point_precomp*)DST[64 + ((-digits_k2[i]) >> 1)], V); eccmadd(V, T); }
        else if (digits_k2[i] > 0) { eccmadd((point_precomp*)DST[64 + ((digits_k2[i]) >> 1)], T); }
        if (digits_k3[i] < 0) { eccneg_precomp((point_precomp*)DST[2*64 + ((-digits_k3[i]) >> 1)], V); eccmadd(V, T); }
        else if (digits_k3[i] > 0) { eccmadd((point_precomp*)DST[2*64 + ((digits_k3[i]) >> 1)], T); }
        if (digits_k4[i] < 0) { eccneg_precomp((point_precomp*)DST[3*64 + ((-digits_k4[i]) >> 1)], V); eccmadd(V, T); }
        else if (digits_k4[i] > 0) { eccmadd((point_precomp*)DST[3*64 + ((digits_k4[i]) >> 1)], T); }
    }

    eccnorm(T, Q);
    return TRUE;
}

/* R = 392*R (FourQ cofactor 392 = 2^3 * 7^2); mirrors core cofactor_clearing(). */
static void cofactor_clearing(point_extproj_t R) {
    point_extproj_precomp_t Q;

    R1_to_R2(R, Q);                      /* (X,Y,Z,Ta,Tb) -> (X+Y,Y-X,2Z,2dT) */
    eccdouble(R);                        /* P = 2*P */
    eccadd(Q, R);                        /* P = P+Q */
    eccdouble(R);
    eccdouble(R);
    eccdouble(R);
    eccdouble(R);
    eccadd(Q, R);
    eccdouble(R);
    eccdouble(R);
    eccdouble(R);
}

static void encode(point_t P, unsigned char* Pencoded) {
    const uint64_t temp1 = (P->x[1][1] & 0x4000000000000000ULL) << 1;
    const uint64_t temp2 = (P->x[0][1] & 0x4000000000000000ULL) << 1;
    copyMem(Pencoded, P->y, 32);
    if (!P->x[0][0] && !P->x[0][1]) {
        uint64_t lane;
        copyMem(&lane, Pencoded + 24, 8); lane |= temp1; copyMem(Pencoded + 24, &lane, 8);
    } else {
        uint64_t lane;
        copyMem(&lane, Pencoded + 24, 8); lane |= temp2; copyMem(Pencoded + 24, &lane, 8);
    }
}

static bool_t decode(const unsigned char* Pencoded, point_t P) {
    felm_t r, t, t0, t1, t2, t3, t4;
    f2elm_t u, v;
    point_extproj_t R;
    unsigned int i;

    copyMem(P->y, Pencoded, 32);
    P->y[1][1] &= 0x7FFFFFFFFFFFFFFFULL;

    fp2sqr1271(P->y, u);
    fp2mul1271(u, (felm_t*)&PARAMETER_d, v);
    fp2sub1271(u, (felm_t*)&ONE, u);
    fp2add1271(v, (felm_t*)&ONE, v);

    fpsqr1271(v[0], t0);
    fpsqr1271(v[1], t1);
    fpadd1271(t0, t1, t0);
    fpmul1271(u[0], v[0], t1);
    fpmul1271(u[1], v[1], t2);
    fpadd1271(t1, t2, t1);
    fpmul1271(u[1], v[0], t2);
    fpmul1271(u[0], v[1], t3);
    fpsub1271(t2, t3, t2);
    fpsqr1271(t1, t3);
    fpsqr1271(t2, t4);
    fpadd1271(t3, t4, t3);
    for (i = 0; i < 125; i++) fpsqr1271(t3, t3);

    fpadd1271(t1, t3, t);
    mod1271(t);
    if (!t[0] && !t[1]) fpsub1271(t1, t3, t);
    fpadd1271(t, t, t);
    fpsqr1271(t0, t3);
    fpmul1271(t0, t3, t3);
    fpmul1271(t, t3, t3);
    fpexp1251(t3, r);
    fpmul1271(t0, r, t3);
    fpmul1271(t, t3, P->x[0]);
    fpsqr1271(P->x[0], t1);
    fpmul1271(t0, t1, t1);

    {
        uint64_t mask, temp[2];
        unsigned char cc;
        mask = (0 - (1 & P->x[0][0]));
        cc = addcarry64(0, P->x[0][0], mask, &temp[0]);
        addcarry64(cc, P->x[0][1], (mask >> 1), &temp[1]);
        P->x[0][0] = shiftright128(temp[0], temp[1], 1);
        P->x[0][1] = (temp[1] >> 1);
    }

    fpmul1271(t2, t3, P->x[1]);

    fpsub1271(t, t1, t);
    mod1271(t);
    if (t[0] || t[1]) {
        t0[0] = P->x[0][0]; t0[1] = P->x[0][1];
        P->x[0][0] = P->x[1][0]; P->x[0][1] = P->x[1][1];
        P->x[1][0] = t0[0]; P->x[1][1] = t0[1];
    }

    mod1271(P->x[0]);
    if (((unsigned int)(Pencoded[31] >> 7))
        != (unsigned int)(P->x[(!P->x[0][0] && !P->x[0][1]) ? 1 : 0][1] >> 62))
        fp2neg1271(P->x);

    point_setup(P, R);
    if (!ecc_point_validate(R)) {
        fpneg1271(R->x[1]);
        P->x[1][0] = R->x[1][0];
        P->x[1][1] = R->x[1][1];
        if (!ecc_point_validate(R)) return FALSE;
    }
    return TRUE;
}

static bool_t verify(const unsigned char* publicKey, const unsigned char* messageDigest, const unsigned char* signature) {
    point_t A;
    unsigned char temp[32 + 64], h[64];

    if ((publicKey[15] & 0x80) || (signature[15] & 0x80)) return FALSE;

    /* Reject non-canonical signature scalars: require S < curve_order r. */
    {
        uint64_t s[4];
        copyMem(s, signature + 32, 32);
        static const uint64_t r[4] = { CURVE_ORDER_0, CURVE_ORDER_1, CURVE_ORDER_2, CURVE_ORDER_3 };
        bool_t canonical = FALSE;
        for (int i = 3; i >= 0; --i) {
            if (s[i] < r[i]) { canonical = TRUE; break; }
            if (s[i] > r[i]) { break; }
        }
        if (!canonical) return FALSE;
    }

    /* Reject the neutral point (01 00..00): one forged (R,S) would verify for every message. */
    /* Like core, pk[0] is not inspected; the top limb's sign bit is masked. */
    {
        uint64_t pk[4];
        copyMem(pk, publicKey, 32);
        if (pk[1] == 0 && pk[2] == 0
            && (pk[3] & 0x7FFFFFFFFFFFFFFFULL) == 0) {
            return FALSE;
        }
    }

    if (!decode(publicKey, A)) return FALSE;

    /* Reject low-order (weak) keys: order dividing cofactor 392 allows forgery, so require [392]*A != neutral. */
    /* Neutral has projective X == 0 (Z never 0), so test reduced X and skip eccnorm's inversion. */
    {
        point_extproj_t cofactorMultiple;
        point_setup(A, cofactorMultiple);
        cofactor_clearing(cofactorMultiple);             /* cofactorMultiple = 392 * A */
        mod1271(cofactorMultiple->x[0]);
        mod1271(cofactorMultiple->x[1]);
        if ((cofactorMultiple->x[0][0] | cofactorMultiple->x[0][1]
            | cofactorMultiple->x[1][0] | cofactorMultiple->x[1][1]) == 0) { /* [392]*A == neutral? */
            return FALSE;
        }
    }

    copyMem(temp, signature, 32);
    copyMem(temp + 32, publicKey, 32);
    copyMem(temp + 64, messageDigest, 32);

    KangarooTwelve(temp, 32 + 64, h, 64);

    {
        uint64_t s[4], hh[8];
        copyMem(s, signature + 32, 32);
        copyMem(hh, h, 64);
        if (!ecc_mul_double(s, hh, A)) return FALSE;
    }

    {
        unsigned char enc[32];
        encode(A, enc);
        return memcmp(enc, signature, 32) == 0;
    }
}

/* ===================== FFI entry points ===================== */

/* Returns 1 if valid, 0 otherwise. */
int fourq_verify(const unsigned char* publicKey,
                 const unsigned char* signature,
                 const unsigned char* messageDigest) {
    return verify(publicKey, messageDigest, signature) ? 1 : 0;
}

int fourq_verify_signature(const unsigned char* publicKey,
                           const unsigned char* signature,
                           const unsigned char* data,
                           unsigned long long dataLen) {
    unsigned char messageDigest[32] = {0};
    KangarooTwelve(data, (unsigned int)dataLen, messageDigest, 32);
    return verify(publicKey, messageDigest, signature) ? 1 : 0;
}

/* K12 with 32-byte output for the guest; in may be unaligned, out32 should be 8-byte aligned. */
void qubic_k12(const unsigned char* in, size_t inLen, unsigned char* out32) {
    KangarooTwelve(in, (unsigned int)inLen, out32, 32);
}
