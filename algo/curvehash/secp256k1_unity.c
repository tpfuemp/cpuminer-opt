/*
 * Unity build of the vendored libsecp256k1 (MIT) for the curvehash PoW.
 *
 *   FIELD_5X52 + SCALAR_4X64  -> 64-bit limbs, 128-bit accumulators (default)
 *   FIELD_10X26 + SCALAR_8X32 -> 32-bit fallback (armv7, any no-int128 target)
 *   NUM_NONE                  -> no GMP dependency
 *   FIELD/SCALAR_INV_BUILTIN  -> self-contained modular inverse
 *
 * USE_ECMULT_STATIC_PRECOMPUTATION is deliberately left undefined: the
 * ecmult_gen table is then built at runtime in secp256k1_context_create, so
 * there is no gen_context codegen stage to wire into the autotools build.
 *
 * Both limb configs must stay exercised, not just the one this host picks:
 * -DCURVEHASH_FORCE_FIELD_10X26 selects 32-bit limbs on a 64-bit host, and
 * -DCURVEHASH_NO_ASM takes 5x52 without the x86-64 assembly. All configurations
 * must produce identical digests.
 */

#define USE_NUM_NONE 1
#define USE_FIELD_INV_BUILTIN 1
#define USE_SCALAR_INV_BUILTIN 1

#if defined(__SIZEOF_INT128__) && !defined(CURVEHASH_FORCE_FIELD_10X26)
  /* The 64-bit limb code uses uint128_t, which this vintage of the library
   * only typedefs behind HAVE___INT128 (util.h) -- a macro its own configure
   * set. We pick the limb width, so we owe it the matching macro. */
  #define HAVE___INT128 1
  #define USE_FIELD_5X52 1
  #define USE_SCALAR_4X64 1
  #if defined(__x86_64__) && !defined(CURVEHASH_NO_ASM)
    #define USE_ASM_X86_64 1
  #endif
#else
  #define USE_FIELD_10X26 1
  #define USE_SCALAR_8X32 1
#endif

/* Our autotools build defines HAVE_CONFIG_H project-wide; without this undef
 * the vendored util.h pulls a libsecp256k1-config.h that does not exist. */
#undef HAVE_CONFIG_H

#include "secp256k1/src/secp256k1.c"

/* Which config actually got compiled. The selection macros are visible only
 * inside this TU, so anything outside testing them reports the #else branch
 * and lies -- ask here instead. */
const char *curvehash_secp256k1_config( void )
{
#if defined(USE_FIELD_5X52)
  #if defined(USE_ASM_X86_64)
   return "field 5x52, scalar 4x64, x86-64 asm";
  #else
   return "field 5x52, scalar 4x64, no asm";
  #endif
#else
   return "field 10x26, scalar 8x32 (32-bit limbs)";
#endif
}
