/*
 * curvehash's k*G kernel -- the extracted subset of the vendored libsecp256k1.
 *
 * curvehash is eight secp256k1 scalar multiplications per nonce, so nearly all
 * of its runtime is inside the vendored library. This TU includes the vendored
 * headers but owns the call sequence, which keeps every tuning change in code
 * we maintain and lets the tree under secp256k1/ stay byte-identical to
 * upstream. Never edit the vendored source in place.
 *
 * Only k*G-plus-serialize is reached. Deliberately absent: secp256k1.c (the
 * public API), ecdsa*, ecmult* (general k*P), ecmult_const*, eckey*, num_gmp*,
 * testrand*.
 *
 * secp256k1_unity.c stays in the binary as a differential oracle: at startup
 * curvehash_self_test() runs random scalars through both and requires identical
 * 65-byte points. That is stronger than a KAT alone, because a k*G that is
 * wrong for only some scalars still yields a well-formed digest.
 */

#include "secp256k1-config.h"

#include "curvehash-kernel.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/* Include via the explicit secp256k1/src/ prefix, NOT via the library's own
 * -I root. A quoted include resolves from the includer's directory first, so
 * these files then find their siblings (util.h, field.h, ...) inside the
 * vendored tree -- rather than anything of the same name that -I. might pull
 * out of the repo root. */
/* group_impl.h has `const int CURVE_B = 7;` -- no `static`, an upstream wart
 * (later libsecp256k1 made it a macro). It was harmless while exactly one TU
 * compiled the library; now that two do, it is a duplicate-symbol link error.
 * Rename ours instead of patching the vendored file. */
#define CURVE_B curvehash_kernel_CURVE_B

#include "secp256k1/include/secp256k1.h"
#include "secp256k1/src/util.h"
#include "secp256k1/src/field_impl.h"
#include "secp256k1/src/scalar_impl.h"
#include "secp256k1/src/group_impl.h"
#include "secp256k1/src/ecmult_gen_impl.h"

static secp256k1_ecmult_gen_context curvehash_gen_ctx;
static bool curvehash_gen_ready = false;

/* 8-bit window table.
 *
 * Upstream uses 64 windows of 4 bits: 64 point additions per scalar multiply.
 * At 8 bits that is 32 windows and 32 additions -- half the dominant cost,
 * traded for a table 8x larger (32 x 256 x 64 B = 512 KB instead of 64 KB).
 * Built once at registration, read-only afterwards, shared by every thread.
 *
 * -DCURVEHASH_FORCE_W4 keeps the 4-bit path and its 64 KB table. */
#define CURVEHASH_W8_WINDOWS 32
#define CURVEHASH_W8_ENTRIES 256

#if !defined(CURVEHASH_FORCE_W4) && !defined(CURVEHASH_FORCE_CT_ECMULT)
  #define CURVEHASH_USE_W8 1
#endif

#ifdef CURVEHASH_USE_W8
static secp256k1_ge_storage (*curvehash_prec8)[CURVEHASH_W8_ENTRIES] = NULL;
static void *curvehash_prec8_raw = NULL;
#endif

/* checked_malloc() calls this on OOM. The library's own default would longjmp
 * out through a callback we do not install, so give it somewhere real to go:
 * this runs once at startup, and a miner with no memory for its tables has
 * nothing useful left to do. */
static void curvehash_kernel_oom( const char *text, void *data )
{
   (void)data;
   fprintf( stderr, "curvehash kernel: %s\n", text );
   abort();
}

static const secp256k1_callback curvehash_kernel_cb =
   { curvehash_kernel_oom, NULL };

/*
 * Point addition.
 *
 * secp256k1_gej_add_ge is the branchless unified add/double formula: it
 * computes the degenerate cases unconditionally and cmovs the answer, so no
 * branch or memory access depends on the point values. gej_add_ge_var is the
 * same sum with fewer operations, but branches -- it early-outs on infinity and
 * delegates doubling to gej_double_var.
 *
 * Both yield the same affine point, so the digest is identical; they differ
 * only in timing. Taking the variable-time one is safe here for the same reason
 * the direct table index is: the scalar is SHA-256 of a PUBLIC block header, so
 * there is no secret to leak and no attacker to time.
 *
 * -DCURVEHASH_FORCE_CT_ADD restores upstream's constant-time addition.
 */
#if defined(CURVEHASH_FORCE_CT_ADD)
  #define CURVEHASH_ADD_GE( r, a, b ) secp256k1_gej_add_ge( (r), (a), (b) )
  #define CURVEHASH_ADD_DESC ", constant-time add (forced)"
#else
  #define CURVEHASH_ADD_GE( r, a, b ) secp256k1_gej_add_ge_var( (r), (a), (b), NULL )
  #define CURVEHASH_ADD_DESC ", vartime add"
#endif

/*
 * Variable-time k*G.
 *
 * Upstream reads ALL sixteen entries of every 4-bit window and cmovs the one it
 * wants, so the index leaks nothing through the cache. This indexes the entry
 * directly instead.
 *
 * ⚠️⚠️ THIS FUNCTION IS NOT SAFE FOR SIGNING. ⚠️⚠️
 * It leaks the scalar through the data cache, by design. That is fine here and
 * ONLY here: curvehash's scalar is SHA-256 of a *public* block header, there is
 * no secret and no attacker to time. If anything in this tree ever wants
 * secp256k1 for a signature, a key derivation, or anything with a private key,
 * it must use the pristine vendored library (secp256k1_unity.c) and NOT this
 * kernel. Using this for a real key is a key-extraction bug, not a slow path.
 *
 * Blinding is kept: it costs nothing measurable, so dropping it would deviate
 * from upstream for no gain.
 */
#ifdef CURVEHASH_USE_W8
/*
 * Build prec8[j][i] = i * (256^j) * G + n_j, for j < 32.
 *
 * The n_j are upstream's "nothing up my sleeve" offsets, which exist so that
 * the i == 0 entry is a real point rather than infinity (gej_add_ge cannot take
 * an infinite b). They must cancel: n_j = 2^j * N for j < 31, and
 * n_31 = N - 2^31 * N, so sum(n_j) = (2^31 - 1)N - 2^31 N + N = 0. Upstream
 * does the same with 64 windows and negates at j == 62; the 32-window analogue
 * negates at j == 30.
 */
static bool curvehash_build_w8( void )
{
   secp256k1_gej *precj = NULL;
   secp256k1_ge  *prec  = NULL;
   secp256k1_gej gbase, numsbase, nums_gej;
   const size_t n = (size_t)CURVEHASH_W8_WINDOWS * CURVEHASH_W8_ENTRIES;
   size_t bytes = sizeof( secp256k1_ge_storage ) * n;
   int i, j, ok;

   {
      static const unsigned char nums_b32[33] =
         "The scalar for this x is unknown";
      secp256k1_fe nums_x;
      secp256k1_ge nums_ge;

      ok = secp256k1_fe_set_b32( &nums_x, nums_b32 );
      if ( !ok ) return false;
      ok = secp256k1_ge_set_xo_var( &nums_ge, &nums_x, 0 );
      if ( !ok ) return false;
      secp256k1_gej_set_ge( &nums_gej, &nums_ge );
      /* Add G to make the bits in x uniformly distributed. */
      secp256k1_gej_add_ge_var( &nums_gej, &nums_gej,
                                &secp256k1_ge_const_g, NULL );
   }

   /* 64-byte alignment by hand: a ge_storage is exactly one cache line, and
    * malloc's 16-byte alignment would make ~3 of every 4 entries straddle two
    * lines -- which matters for 512 KB of random access. No aligned_alloc:
    * this has to build under MinGW too. */
   curvehash_prec8_raw = malloc( bytes + 64 );
   precj = (secp256k1_gej*)malloc( sizeof( secp256k1_gej ) * n );
   prec  = (secp256k1_ge*) malloc( sizeof( secp256k1_ge  ) * n );
   if ( !curvehash_prec8_raw || !precj || !prec )
   {
      free( curvehash_prec8_raw ); free( precj ); free( prec );
      curvehash_prec8_raw = NULL;
      return false;
   }
   curvehash_prec8 = (secp256k1_ge_storage (*)[CURVEHASH_W8_ENTRIES])
      ( ( (uintptr_t)curvehash_prec8_raw + 63 ) & ~(uintptr_t)63 );

   secp256k1_gej_set_ge( &gbase, &secp256k1_ge_const_g );   /* 256^j * G */
   numsbase = nums_gej;                                     /* 2^j * nums */

   for ( j = 0; j < CURVEHASH_W8_WINDOWS; j++ )
   {
      const int base = j * CURVEHASH_W8_ENTRIES;

      precj[base] = numsbase;
      for ( i = 1; i < CURVEHASH_W8_ENTRIES; i++ )
         secp256k1_gej_add_var( &precj[base+i], &precj[base+i-1], &gbase, NULL );

      for ( i = 0; i < 8; i++ )      /* gbase *= 256 */
         secp256k1_gej_double_var( &gbase, &gbase, NULL );

      secp256k1_gej_double_var( &numsbase, &numsbase, NULL );
      if ( j == CURVEHASH_W8_WINDOWS - 2 )
      {
         secp256k1_gej_neg( &numsbase, &numsbase );
         secp256k1_gej_add_var( &numsbase, &numsbase, &nums_gej, NULL );
      }
   }

   secp256k1_ge_set_all_gej_var( prec, precj, n, &curvehash_kernel_cb );
   for ( j = 0; j < CURVEHASH_W8_WINDOWS; j++ )
      for ( i = 0; i < CURVEHASH_W8_ENTRIES; i++ )
         secp256k1_ge_to_storage( &curvehash_prec8[j][i],
                                  &prec[j*CURVEHASH_W8_ENTRIES + i] );

   free( precj );
   free( prec );
   return true;
}

/* 32 windows of 8 bits. Blinding comes from the vendored context: r starts at
 * ctx->initial == -blind*G and the scalar is gn + blind, so the offsets and the
 * blind both cancel and the result is gn*G. */
static void curvehash_ecmult_gen_w8( const secp256k1_ecmult_gen_context *ctx,
                                     secp256k1_gej *r,
                                     const secp256k1_scalar *gn )
{
   secp256k1_ge add;
   secp256k1_scalar gnb;
   int bits;
   int j;

   *r = ctx->initial;
   secp256k1_scalar_add( &gnb, gn, &ctx->blind );

   for ( j = 0; j < CURVEHASH_W8_WINDOWS; j++ )
   {
      /* offset is a multiple of 8, so the 8 bits never cross a limb boundary
       * -- which is what scalar_get_bits requires. */
      bits = secp256k1_scalar_get_bits( &gnb, j * 8, 8 );
      secp256k1_ge_from_storage( &add, &curvehash_prec8[j][bits] );
      CURVEHASH_ADD_GE( r, r, &add );
   }

   secp256k1_ge_clear( &add );
   secp256k1_scalar_clear( &gnb );
}
#endif   /* CURVEHASH_USE_W8 */

/* Which scalar multiply the whole file uses. All three are correct and produce
 * identical points; they differ in timing behaviour and table size. */
#if defined(CURVEHASH_FORCE_CT_ECMULT)
  #define CURVEHASH_ECMULT_GEN secp256k1_ecmult_gen
#elif defined(CURVEHASH_FORCE_W4)
  #define CURVEHASH_ECMULT_GEN curvehash_ecmult_gen
#else
  #define CURVEHASH_ECMULT_GEN curvehash_ecmult_gen_w8
#endif

static void curvehash_ecmult_gen( const secp256k1_ecmult_gen_context *ctx,
                                  secp256k1_gej *r, const secp256k1_scalar *gn )
{
   secp256k1_ge add;
   secp256k1_scalar gnb;
   int bits;
   int j;

   *r = ctx->initial;
   /* Blind scalar/point multiplication by computing (n-b)G + bG instead of nG. */
   secp256k1_scalar_add( &gnb, gn, &ctx->blind );

   for ( j = 0; j < 64; j++ )
   {
      bits = secp256k1_scalar_get_bits( &gnb, j * 4, 4 );
      /* The whole point of item 2: index, do not scan. ge_from_storage sets
       * add.infinity itself. */
      secp256k1_ge_from_storage( &add, &(*ctx->prec)[j][bits] );
      CURVEHASH_ADD_GE( r, r, &add );
   }

   bits = 0;
   (void)bits;
   secp256k1_ge_clear( &add );
   secp256k1_scalar_clear( &gnb );
}

bool curvehash_kernel_init( void )
{
   if ( curvehash_gen_ready )
      return true;

   secp256k1_ecmult_gen_context_init( &curvehash_gen_ctx );
   /* Builds the 64 KB 4-bit-window table and sets up the blinding scalar. */
   secp256k1_ecmult_gen_context_build( &curvehash_gen_ctx,
                                       &curvehash_kernel_cb );
   if ( !secp256k1_ecmult_gen_context_is_built( &curvehash_gen_ctx ) )
      return false;

#ifdef CURVEHASH_USE_W8
   /* Needs the 4-bit context first: ctx->initial / ctx->blind are set up by
    * the build above, and the 8-bit path reuses them. */
   if ( !curvehash_build_w8() )
      return false;
#endif

   curvehash_gen_ready = true;
   return true;
}

int curvehash_kg65( unsigned char out65[65], const unsigned char sec32[32] )
{
   secp256k1_scalar sec;
   secp256k1_gej pj;
   secp256k1_ge p;
   int overflow;

   secp256k1_scalar_set_b32( &sec, sec32, &overflow );
   if ( overflow || secp256k1_scalar_is_zero( &sec ) )
      return 0;

   CURVEHASH_ECMULT_GEN( &curvehash_gen_ctx, &pj, &sec );
   secp256k1_ge_set_gej( &p, &pj );

   /* ge_set_gej leaves x/y reduced but not normalized; fe_get_b32 requires
    * normalized input. _var is fine here -- the value is public. */
   secp256k1_fe_normalize_var( &p.x );
   secp256k1_fe_normalize_var( &p.y );

   out65[0] = 0x04;
   secp256k1_fe_get_b32( out65 + 1,  &p.x );
   secp256k1_fe_get_b32( out65 + 33, &p.y );

   secp256k1_scalar_clear( &sec );
   return 1;
}

void curvehash_kg65_batch( unsigned char out65[][65],
                           const unsigned char sec32[][32],
                           int lanes, uint32_t *active )
{
   secp256k1_gej pj[CURVEHASH_MAX_LANES];
   secp256k1_fe  z [CURVEHASH_MAX_LANES];
   secp256k1_fe  zi[CURVEHASH_MAX_LANES];
   int idx[CURVEHASH_MAX_LANES];
   int cnt = 0;
   uint32_t act = *active;
   int l, k;

   if ( lanes > CURVEHASH_MAX_LANES ) lanes = CURVEHASH_MAX_LANES;

   for ( l = 0; l < lanes; l++ )
   {
      secp256k1_scalar sec;
      int overflow;

      if ( !( act & ( 1u << l ) ) )
         continue;

      secp256k1_scalar_set_b32( &sec, sec32[l], &overflow );
      if ( overflow || secp256k1_scalar_is_zero( &sec ) )
      {
         /* ~2^-128. Drop this lane and keep going: one bad scalar must not
          * cost the whole batch. */
         act &= ~( 1u << l );
         continue;
      }

      CURVEHASH_ECMULT_GEN( &curvehash_gen_ctx, &pj[l], &sec );
      z[cnt]   = pj[l].z;
      idx[cnt] = l;
      cnt++;
      secp256k1_scalar_clear( &sec );
   }

   if ( cnt )
   {
      /* The whole point of this function: ONE modular inversion for the batch,
       * plus ~3 multiplications per lane (Montgomery). Upstream's own routine,
       * the same one ge_set_all_gej_var uses to build the generator table. */
      secp256k1_fe_inv_all_var( zi, z, (size_t)cnt );

      for ( k = 0; k < cnt; k++ )
      {
         secp256k1_ge p;

         l = idx[k];
         secp256k1_ge_set_gej_zinv( &p, &pj[l], &zi[k] );
         secp256k1_fe_normalize_var( &p.x );
         secp256k1_fe_normalize_var( &p.y );
         out65[l][0] = 0x04;
         secp256k1_fe_get_b32( out65[l] + 1,  &p.x );
         secp256k1_fe_get_b32( out65[l] + 33, &p.y );
      }
   }

   *active = act;
}

const char *curvehash_kernel_config( void )
{
#if defined(CURVEHASH_FORCE_CT_ECMULT)
   /* Upstream's secp256k1_ecmult_gen, which does its own constant-time
    * addition -- CURVEHASH_ADD_GE is not on this path, so do not report it. */
   return CURVEHASH_SECP256K1_CONFIG ", constant-time gen, 4-bit window (forced)";
#elif defined(CURVEHASH_FORCE_W4)
   return CURVEHASH_SECP256K1_CONFIG ", vartime gen, 4-bit window (forced)"
          CURVEHASH_ADD_DESC;
#else
   return CURVEHASH_SECP256K1_CONFIG ", vartime gen, 8-bit window (512 KB)"
          CURVEHASH_ADD_DESC;
#endif
}
