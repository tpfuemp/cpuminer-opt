/* Decides whether VerusHash can be built for this target and which intrinsic
 * header the vendored sources get. Without hardware AES + carryless multiply the
 * whole implementation compiles out and register_verus_algo() says why: no
 * software fallback, since emulating 32 AES+CLMUL rounds per hash would be far
 * too slow to mine with and would only mask a misconfigured build. */
#ifndef VERUS_SIMD_H
#define VERUS_SIMD_H

#if defined(__AES__) && defined(__PCLMUL__)

#define VERUS_HAVE_SIMD 1
#include <immintrin.h>

#elif defined(__aarch64__) && ( defined(__ARM_FEATURE_CRYPTO) \
     || ( defined(__ARM_FEATURE_AES) && defined(__ARM_FEATURE_PMULL) ) )

#define VERUS_HAVE_SIMD 1
/* upstream's own "not x86" macro; it already guards the cpuid helper in
 * verus_clhash.h, which is x86-only and unused here. */
#define ARM 1
#include "verus-neon.h"

#endif

#endif  /* VERUS_SIMD_H */
