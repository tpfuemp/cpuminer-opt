// HoohashV110 (PePePoW) proof-of-work, ported into cpuminer-opt.
//
// Algorithm + the FP math below are adapted verbatim (consensus-critical, must
// stay bit-identical) from the MIT-licensed reference:
//   github.com/MattF42/PePePow_multi-hashing  crypto/hoohash/hoohash.c
//   Copyright (c) 2024 Hoosat Oy
//   Copyright (c) 2024 PePe-core developers
//   Adapted from github.com/HoosatNetwork/hoohash commit 9634f114.
//
// FP DETERMINISM: the matrix multiply uses double-precision sin/cos/exp/sqrt
// with a NaN/Inf rejection loop. -ffast-math / -Ofast imply -ffinite-math-only,
// which folds isnan/isinf to false and breaks that loop -> a different (wrong)
// digest. cpuminer-opt uses one global CFLAGS (and -Ofast on ARM), so we pin
// strict FP for THIS translation unit only.

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC optimize ("no-fast-math")
#endif
#if defined(__clang__)
#pragma clang fp contract(off)
#endif
#pragma STDC FP_CONTRACT OFF

#include "hoohash-gate.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

#include "algo/blake3/blake3.h"

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
#define PI 3.14159265358979323846
#define EPS 1e-9
#define COMPLEX_TRANSFORM_MULTIPLIER 0.000001

// xoshiro256** PRNG state
typedef struct {
    uint64_t s0;
    uint64_t s1;
    uint64_t s2;
    uint64_t s3;
} xoshiro_state;

// Safe memory read functions to avoid UB from unaligned access
static inline uint64_t read_uint64_le(const uint8_t *data) {
    uint64_t result = 0;
    for (int i = 0; i < 8; i++) {
        result |= ((uint64_t)data[i]) << (i * 8);
    }
    return result;
}

static inline uint32_t read_uint32_le(const uint8_t *data) {
    return ((uint32_t)data[0]) |
           ((uint32_t)data[1] << 8) |
           ((uint32_t)data[2] << 16) |
           ((uint32_t)data[3] << 24);
}

static inline uint32_t read_uint32_be(const uint8_t *data) {
    return ((uint32_t)data[0] << 24) |
           ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) |
           (uint32_t)data[3];
}

// xoshiro256** functions
static inline uint64_t rotl64(const uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
}

static void xoshiro_init(xoshiro_state *state, const uint8_t *bytes) {
    state->s0 = read_uint64_le(&bytes[0]);
    state->s1 = read_uint64_le(&bytes[8]);
    state->s2 = read_uint64_le(&bytes[16]);
    state->s3 = read_uint64_le(&bytes[24]);
}

static uint64_t xoshiro_gen(xoshiro_state *x) {
    uint64_t res = rotl64(x->s0 + x->s3, 23) + x->s0;
    uint64_t t = x->s1 << 17;

    x->s2 ^= x->s0;
    x->s3 ^= x->s1;
    x->s1 ^= x->s2;
    x->s0 ^= x->s3;

    x->s2 ^= t;
    x->s3 = rotl64(x->s3, 45);

    return res;
}

// Complex nonlinear transformations
static double MediumComplexNonLinear(double x) {
    return exp(sin(x) + cos(x));
}

static double IntermediateComplexNonLinear(double x) {
    if (fabs(x - PI / 2) < EPS || fabs(x - 3 * PI / 2) < EPS) {
        return 0; // Avoid singularity
    }
    return sin(x) * sin(x);
}

static double HighComplexNonLinear(double x) {
    return 1.0 / sqrt(fabs(x) + 1);
}

static double ComplexNonLinear(double x) {
    double transformFactorOne = (x * COMPLEX_TRANSFORM_MULTIPLIER) / 8.0 - floor((x * COMPLEX_TRANSFORM_MULTIPLIER) / 8.0);
    double transformFactorTwo = (x * COMPLEX_TRANSFORM_MULTIPLIER) / 4.0 - floor((x * COMPLEX_TRANSFORM_MULTIPLIER) / 4.0);

    if (transformFactorOne < 0.33) {
        if (transformFactorTwo < 0.25) {
            return MediumComplexNonLinear(x + (1 + transformFactorTwo));
        } else if (transformFactorTwo < 0.5) {
            return MediumComplexNonLinear(x - (1 + transformFactorTwo));
        } else if (transformFactorTwo < 0.75) {
            return MediumComplexNonLinear(x * (1 + transformFactorTwo));
        } else {
            return MediumComplexNonLinear(x / (1 + transformFactorTwo));
        }
    } else if (transformFactorOne < 0.66) {
        if (transformFactorTwo < 0.25) {
            return IntermediateComplexNonLinear(x + (1 + transformFactorTwo));
        } else if (transformFactorTwo < 0.5) {
            return IntermediateComplexNonLinear(x - (1 + transformFactorTwo));
        } else if (transformFactorTwo < 0.75) {
            return IntermediateComplexNonLinear(x * (1 + transformFactorTwo));
        } else {
            return IntermediateComplexNonLinear(x / (1 + transformFactorTwo));
        }
    } else {
        if (transformFactorTwo < 0.25) {
            return HighComplexNonLinear(x + (1 + transformFactorTwo));
        } else if (transformFactorTwo < 0.5) {
            return HighComplexNonLinear(x - (1 + transformFactorTwo));
        } else if (transformFactorTwo < 0.75) {
            return HighComplexNonLinear(x * (1 + transformFactorTwo));
        } else {
            return HighComplexNonLinear(x / (1 + transformFactorTwo));
        }
    }
}

// NOTE (consensus quirk, preserve verbatim): the rejection loop never recomputes
// `transformedValue`, so the finite path always returns value*1 and the NaN/Inf
// path always returns 0. Do not "fix" this.
static double SafeComplexTransform(double input) {
    double transformedValue;
    double rounds = 1;
    transformedValue = ComplexNonLinear(input);
    while (isnan(transformedValue) || isinf(transformedValue)) {
        input = input * 0.1;
        if (input <= 0.0000000000001) {
            return 0;
        }
        rounds++;
    }
    return transformedValue * rounds;
}

static void generateHoohashMatrix(const uint8_t *hash, double mat[64][64]) {
    xoshiro_state state;
    xoshiro_init(&state, hash);
    double normalize = 1000000.0;
    for (int i = 0; i < 64; i++) {
        for (int j = 0; j < 64; j++) {
            uint64_t val = xoshiro_gen(&state);
            uint32_t lower_4_bytes = val & 0xFFFFFFFF;
            mat[i][j] = (double)lower_4_bytes / (double)UINT32_MAX * normalize;
        }
    }
}

static double TransformFactor(double x) {
    const double granularity = 1024.0;
    return x / granularity - floor(x / granularity);
}

static void ConvertBytesToUint32Array(uint32_t *H, const uint8_t *bytes) {
    for (int i = 0; i < 8; i++) {
        H[i] = read_uint32_be(&bytes[i * 4]);
    }
}

static void HoohashMatrixMultiplication(double mat[64][64], const uint8_t *hashBytes, uint8_t *output, uint64_t nonce) {
    uint8_t scaledValues[32] = {0};
    uint8_t vector[64] = {0};
    double product[64] = {0};
    uint8_t result[32] = {0};
    uint32_t H[8] = {0};

    ConvertBytesToUint32Array(H, hashBytes);
    double hashXor = (double)(H[0] ^ H[1] ^ H[2] ^ H[3] ^ H[4] ^ H[5] ^ H[6] ^ H[7]);
    double nonceMod = (double)(nonce & 0xFF);
    double divider = 0.0001;
    double multiplier = 1234;
    double sw = 0.0;

    for (int i = 0; i < 32; i++) {
        vector[2 * i] = hashBytes[i] >> 4;
        vector[2 * i + 1] = hashBytes[i] & 0x0F;
    }

    for (int i = 0; i < 64; i++) {
        for (int j = 0; j < 64; j++) {
            if (sw <= 0.02) {
                double input = (mat[i][j] * hashXor * (double)vector[j] + nonceMod);
                double output_val = SafeComplexTransform(input) * (double)vector[j] * multiplier;
                product[i] += output_val;
            } else {
                double output_val = mat[i][j] * divider * (double)vector[j];
                product[i] += output_val;
            }
            sw = TransformFactor(product[i]);
        }
    }

    for (int i = 0; i < 64; i += 2) {
        uint64_t pval = (uint64_t)product[i] + (uint64_t)product[i + 1];
        scaledValues[i / 2] = (uint8_t)(pval & 0xFF);
    }

    for (int i = 0; i < 32; i++) {
        result[i] = hashBytes[i] ^ scaledValues[i];
    }

    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, result, HOOHASH_HASH_SIZE);
    blake3_hasher_finalize(&hasher, output, HOOHASH_HASH_SIZE);
}

// Core HoohashV110 over an 80-byte block header.
// firstPass derives from the full header (nonce-dependent); the matrix derives
// from the header with nNonce (4 bytes @ offset 76, LE) zeroed (nonce-
// independent, per the PePePoW consensus change).
static void hoohashv110_core(const uint8_t *data, uint8_t output[HOOHASH_HASH_SIZE])
{
    blake3_hasher hasher;
    uint8_t firstPass[HOOHASH_HASH_SIZE];
    uint8_t matrixSeed[HOOHASH_HASH_SIZE];
    double mat[64][64];

    // First BLAKE3 pass on the full 80-byte header (nonce included).
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, data, 80);
    blake3_hasher_finalize(&hasher, firstPass, HOOHASH_HASH_SIZE);

    // matrixSeed = BLAKE3(header80 with nonce bytes zeroed).
    uint8_t masked_header[80];
    memcpy(masked_header, data, 80);
    memset(masked_header + 76, 0, 4); /* zero nNonce (uint32 LE at offset 76) */

    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, masked_header, 80);
    blake3_hasher_finalize(&hasher, matrixSeed, HOOHASH_HASH_SIZE);

    generateHoohashMatrix(matrixSeed, mat);

    const uint8_t *nonce_ptr = data + 76;
    const uint64_t nonce = (uint64_t)read_uint32_le(nonce_ptr);

    HoohashMatrixMultiplication(mat, firstPass, output, nonce);
}

// cpuminer entry point: `input` is the 80-byte serialized header.
int hoohashv110_hash( void *output, const void *input, int thr_id )
{
    (void)thr_id;
    hoohashv110_core( (const uint8_t*)input, (uint8_t*)output );
    return 1;
}

// ---------------------------------------------------------------------------
// Known-answer self-test + a CRITICAL caveat on this algorithm's determinism.
//
// The matrix multiply feeds sin/cos/exp arguments that routinely reach ~1e16
// (|arg| up to ~3e16 measured). libm argument-reduction at that magnitude is
// NOT portable: different glibc *versions* return different last-ULP results,
// and one divergent transcendental flips the whole digest. So this PoW is
// inherently libm-version-sensitive — "bit-identical across platforms" only
// holds when both sides link compatible libm. Consensus == whatever libm
// PePe-core (the validating daemon) links; matching it is the real requirement,
// and only LIVE POOL shares prove it.
//
// EMPIRICAL FINDINGS:
//  - The anchor header below hashes to a64993e8... bit-identically on x86-64
//    glibc 2.35 AND aarch64 glibc (NanoPi R6S). Stable -> used as the KAT.
//  - Synthetic uniform-random headers (splitmix64) DIVERGED between glibc 2.35
//    and newer glibc (they hit the ~1e16 sin regime), so they are NOT shipped
//    as a hard gate — they live in scratchpad/gen_vectors.c (set NSPLIT>0) for
//    DIAGNOSTIC cross-platform divergence testing only.
//  - A KAT generated with MinGW's libm was simply wrong; never use non-glibc.
//
// The shipped KAT is therefore the single anchor vector: a regression guard
// (catches port/algorithm breakage; the miner refuses to start on mismatch),
// NOT a proof of consensus. TODO: replace/augment with a REAL PePePoW block's
// (header -> known hash) once available, and validate live-pool acceptance.
// If the pool rejects a *fraction* of shares (not all -> that'd be byte order),
// it's this libm divergence -> escalate to bundling a fixed transcendental impl
// matching PePe-core (plan SS3).
// ---------------------------------------------------------------------------
// KAT machine-generated on x86-64 glibc by scratchpad/gen_vectors.c (which links
// this same hoohashv110_hash). Regenerate with that tool; never hand-edit.
// Defines HOOHASH_KAT_COUNT, hoohashv110_kat_input[][80], _kat_expected[][32].
#include "hoohash-kat.h"

bool hoohashv110_self_test( void )
{
   for ( int v = 0; v < HOOHASH_KAT_COUNT; v++ )
   {
      uint8_t hash[32];
      hoohashv110_hash( hash, hoohashv110_kat_input[v], 0 );

      if ( memcmp( hash, hoohashv110_kat_expected[v], 32 ) != 0 )
      {
         char got[65], exp[65];
         for ( int i = 0; i < 32; i++ )
         {
            sprintf( got + i * 2, "%02x", hash[i] );
            sprintf( exp + i * 2, "%02x", hoohashv110_kat_expected[v][i] );
         }
         applog( LOG_ERR, "HoohashV110 self-test FAILED at vector %d "
                          "(FP/consensus mismatch)", v );
         applog( LOG_ERR, "  got:      %s", got );
         applog( LOG_ERR, "  expected: %s", exp );
         return false;
      }
   }

   applog( LOG_NOTICE, "HoohashV110 self-test PASSED (%d/%d glibc KAT vectors)",
           HOOHASH_KAT_COUNT, HOOHASH_KAT_COUNT );
   return true;
}

// ---------------------------------------------------------------------------
// scanhash
//
// CONSENSUS byte order — VERIFIED against a real PePePoW block (height ~0x4734dd,
// 2026-06-28; see scratchpad/verify_block.c + fulltest_harness.c):
//   * Input:  be32enc the 19 header words + nonce. Combined with the standard
//     stratum work-builder (std_build_block_header), this reconstructs the
//     daemon's raw 80-byte serialization byte-for-byte (e.g. version word
//     0x00400020 -> bytes 00 40 00 20). The winning nonce only validates with
//     this exact input.
//   * Output: HoohashV110 (Hoosat/Kaspa-family) compares the digest as a
//     BIG-ENDIAN 256-bit number (byte 0 = MSB) — the OPPOSITE of Bitcoin's
//     reversed convention. cpuminer's valid_hash treats the digest as
//     little-endian uint32 words (word 7 = MSB), so we byte-REVERSE the digest
//     before valid_hash / submit. (Proven: the real block's winning nonce lands
//     under target only after this reversal; a tampered nonce fails.)
// ---------------------------------------------------------------------------
int scanhash_hoohashv110( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(64) hash[8];
   uint32_t _ALIGN(64) hashbe[8];
   uint32_t _ALIGN(64) edata[20];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const int thr_id = mythr->id;
   uint32_t n = first_nonce;
   volatile uint8_t *restart = &( work_restart[thr_id].restart );
   const bool bench = opt_benchmark;

   for ( int i = 0; i < 19; i++ )
      be32enc( &edata[i], pdata[i] );

   do
   {
      be32enc( &edata[19], n );
      hoohashv110_hash( hash, edata, thr_id );

      // Big-endian digest -> little-endian words for cpuminer's comparator.
      for ( int i = 0; i < 32; i++ )
         ( (uint8_t*)hashbe )[i] = ( (uint8_t*)hash )[31 - i];

      if ( unlikely( valid_hash( hashbe, ptarget ) && !bench ) )
      {
         pdata[19] = n;
         submit_solution( work, hashbe, mythr );
      }
      n++;
   } while ( n < max_nonce && !(*restart) );

   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

bool register_hoohashv110_algo( algo_gate_t *gate )
{
   if ( !hoohashv110_self_test() )
   {
      applog( LOG_ERR, "HoohashV110 self-test failed" );
      return false;
   }
   gate->scanhash      = (void*)&scanhash_hoohashv110;
   gate->hash          = (void*)&hoohashv110_hash;
   gate->optimizations = SSE2_OPT | AVX2_OPT | NEON_OPT;
   // Plain 256-bit-output hash: standard Bitcoin difficulty scale (0xffff base).
   // (A 256.0 factor would make targetdiff 256x too easy -> pool rejects shares
   // as "low difficulty"; see the skydoge port notes.)
   opt_target_factor   = 1.0;
   return true;
}
