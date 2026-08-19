/*-
 * Copyright 2018 Cryply team
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Cryply team as part of the Cryply
 * coin.
 */
#include "yespower.h"
#include "yespower-kat.h"
#include "algo-gate-api.h"

yespower_params_t yespower_params;

__thread sha256_context sha256_prehash_ctx;

// ---------------------------------------------------------------- self-test
//
// Ten registered algos share ONE source file compiled TWICE (v0.5 / v1.0)
// across four ISA paths, and a build exercises one ISA path. Without this,
// nothing checks any of them: a mis-specialised build mines well-formed
// digests that the pool silently rejects. Vectors are upstream's own
// (yespower-kat.h).

// NOTE: yespower-opt.c compiles to nothing without __SSE2__ or __aarch64__,
// so on a scalar build `yespower`, `yespower_b2b` and the region helpers do
// not exist. Picking the wrong pair here links fine on x86-64, where __SSE2__
// is always defined, and breaks only on the build nobody tries first.
#if defined(__SSE2__) || defined(__aarch64__)
  #define YESPOWER_KAT_FN       yespower
  #define YESPOWER_KAT_INIT     yespower_init_local
  #define YESPOWER_KAT_FREE     yespower_free_local
  #define YESPOWER_KAT_PATH     "SIMD"
#else
  #define YESPOWER_KAT_FN       yespower_ref
  #define YESPOWER_KAT_INIT     yespower_init_local_ref
  #define YESPOWER_KAT_FREE     yespower_free_local_ref
  #define YESPOWER_KAT_PATH     "reference"
#endif

// work_restart[] is calloc'd in main() AFTER register_algo_gate() runs, and
// yespower() polls work_restart[thrid].restart between phases, so a
// registration-time self-test has to supply one itself.
static struct work_restart yespower_kat_restart[1];

static bool yespower_kat_hash( const yespower_kat_t *v, const uint8_t src[80],
                               yespower_local_t *local, uint8_t out[32] )
{
   yespower_params_t p;

   p.version = v->version;
   p.N       = v->N;
   p.r       = v->r;
   if ( v->pers_is_src )   { p.pers = src;                    p.perslen = 80; }
   else if ( v->pers )     { p.pers = (const uint8_t*)v->pers;
                             p.perslen = strlen( v->pers ); }
   else                    { p.pers = NULL;                   p.perslen = 0;  }

   // The shipping path assumes scanhash already prehashed the first 64 bytes
   // (yespower-opt.c, srclen == 80 branch), so the KAT must do the same. That
   // makes this a test of the prehash optimization too: upstream computed
   // these digests without one.
   sha256_ctx_init( &sha256_prehash_ctx );
   sha256_update( &sha256_prehash_ctx, src, 64 );

   return YESPOWER_KAT_FN( local, src, 80, &p, (yespower_binary_t*)out, 0 ) == 1;
}

static void yespower_kat_log( const char *what, const uint8_t *got,
                              const uint8_t *want )
{
   char g[65], e[65];
   for ( int i = 0; i < 32; i++ )
   {
      sprintf( g + i*2, "%02x", got[i] );
      sprintf( e + i*2, "%02x", want[i] );
   }
   applog( LOG_ERR, "yespower KAT FAILED: %s", what );
   applog( LOG_ERR, "  got:      %s", g );
   applog( LOG_ERR, "  expected: %s", e );
}

// Returns NULL on success, else the name of the failing check.
const char *yespower_self_test( void )
{
   yespower_params_t saved = yespower_params;
   struct work_restart *saved_restart = work_restart;
   yespower_local_t local;
   uint8_t src[80], out[32], ref[32];
   const char *fail = NULL;

   if ( !work_restart ) work_restart = yespower_kat_restart;
   YESPOWER_KAT_INIT( &local );
   yespower_kat_input( src );

   for ( size_t i = 0; i < YESPOWER_NUM_KATS; i++ )
   {
      if ( !yespower_kat_hash( &yespower_kats[i], src, &local, out ) )
      {  fail = yespower_kats[i].name; goto done; }
      if ( memcmp( out, yespower_kats[i].digest, 32 ) )
      {
         yespower_kat_log( yespower_kats[i].name, out, yespower_kats[i].digest );
         fail = yespower_kats[i].name; goto done;
      }
   }

   // Non-vacuity. Byte 10 lies inside the 64-byte prehash and byte 70 outside
   // it, so between them they prove the digest depends on both halves of the
   // header -- a prehash wrongly cached across headers would pass every vector
   // above and fail here.
   memcpy( ref, out, 32 );        // last vector's digest
   for ( int b = 0; b < 2; b++ )
   {
      uint8_t alt[80];
      yespower_kat_input( alt );
      alt[ b ? 70 : 10 ] ^= 0x01;
      if ( !yespower_kat_hash( &yespower_kats[YESPOWER_NUM_KATS-1], alt,
                               &local, out ) )
      {  fail = "non-vacuity (hash failed)"; goto done; }
      if ( !memcmp( out, ref, 32 ) )
      {
         fail = b ? "non-vacuity (byte 70 did not change the digest)"
                  : "non-vacuity (byte 10 did not change the digest)";
         goto done;
      }
   }

done:
   YESPOWER_KAT_FREE( &local );
   yespower_params = saved;
   work_restart    = saved_restart;
   return fail;
}

bool yespower_gate_self_test( void )
{
   const char *fail = yespower_self_test();
   if ( fail )
   {
      applog( LOG_ERR, "yespower self-test FAILED (%s path): %s",
              YESPOWER_KAT_PATH, fail );
      return false;
   }
   applog( LOG_NOTICE,
           "yespower self-test PASSED (%s path, %d upstream vectors)",
           YESPOWER_KAT_PATH, (int)YESPOWER_NUM_KATS );
   return true;
}

// The blake2b variants have no published vectors, so anchor them against the
// in-tree reference instead. yespower-blake2b-ref.c is compiled into every
// build and shares nothing with the optimized path below the blake2b bracket,
// so agreement is real evidence. Runs at the caller's own N/r.
static bool yespower_b2b_self_test( void )
{
   struct work_restart *saved_restart = work_restart;
   yespower_local_t la, lb;
   uint8_t src[80];
   yespower_binary_t opt, ref;
   bool ok = false;

   if ( !work_restart ) work_restart = yespower_kat_restart;
   yespower_b2b_init_local_ref( &lb );
   yespower_kat_input( src );

#if defined(__SSE2__) || defined(__aarch64__)
   yespower_init_local( &la );
   if (    yespower_b2b(     &la, src, 80, &yespower_params, &opt, 0 ) == 1
        && yespower_b2b_ref( &lb, src, 80, &yespower_params, &ref, 0 ) == 1 )
      ok = !memcmp( &opt, &ref, sizeof opt );

   if ( !ok )
      yespower_kat_log( "yespower-b2b vs reference implementation",
                        opt.uc, ref.uc );
   yespower_free_local( &la );
#else
   // Scalar build: register_power2b_algo installs yespower_b2b_hash_ref, so
   // the reference IS the shipping path and there is no second implementation
   // to difference it against. Smoke-test it instead -- that is honestly all
   // this build can check, and it is still worth doing: the bug this test was
   // written to catch (a 12 KiB heap overread from a missing cast in
   // yespower-blake2b-ref.c) lived on exactly this path.
   (void)la; (void)opt;
   ok = yespower_b2b_ref( &lb, src, 80, &yespower_params, &ref, 0 ) == 1;
#endif

   yespower_b2b_free_local_ref( &lb );
   work_restart = saved_restart;

   if ( !ok )
   {
      applog( LOG_ERR, "yespower-b2b self-test FAILED (N=%d r=%d)",
              yespower_params.N, yespower_params.r );
      return false;
   }
   applog( LOG_NOTICE,
           "yespower-b2b self-test PASSED (%s, N=%d r=%d)",
#if defined(__SSE2__) || defined(__aarch64__)
           "differential vs reference",
#else
           "reference path smoke test -- no oracle on a scalar build",
#endif
           yespower_params.N, yespower_params.r );
   return true;
}


#if defined(__SSE2__) || defined(__aarch64__)

int yespower_hash( const char *input, char *output, int thrid )
{
   return yespower_tls( input, 80, &yespower_params,
           (yespower_binary_t*)output, thrid );
}

#else

int yespower_hash_ref( const char *input, char *output, int thrid )
{
   return yespower_tls_ref( input, 80, &yespower_params,
           (yespower_binary_t*)output, thrid );
}

#endif

// YESPOWER

int scanhash_yespower( struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(64) vhash[8];
   uint32_t _ALIGN(64) endiandata[20];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;

   for ( int k = 0; k < 19; k++ )
      be32enc( &endiandata[k], pdata[k] );
   endiandata[19] = n;

   // do sha256 prehash
   sha256_ctx_init( &sha256_prehash_ctx );
   sha256_update( &sha256_prehash_ctx, endiandata, 64 );

   do {
      if ( algo_gate.hash( (char*)endiandata, (char*)vhash, thr_id ) )
      if unlikely( valid_hash( vhash, ptarget ) && !opt_benchmark )
      {
          be32enc( pdata+19, n );
          submit_solution( work, vhash, mythr );
      }
      endiandata[19] = ++n;
   } while ( n < last_nonce && !work_restart[thr_id].restart );
   *hashes_done = n - first_nonce;
   pdata[19] = n;
   return 0;
}

// YESPOWER-B2B

#if defined(__SSE2__) || defined(__aarch64__)

int yespower_b2b_hash( const char *input, char *output, int thrid )
{
  return yespower_b2b_tls( input, 80, &yespower_params, (yespower_binary_t*)output, thrid );
}

#else

int yespower_b2b_hash_ref( const char *input, char *output, int thrid )
{
  return yespower_b2b_tls_ref( input, 80, &yespower_params, (yespower_binary_t*)output, thrid );
}

#endif

int scanhash_yespower_b2b( struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(64) vhash[8];
   uint32_t _ALIGN(64) endiandata[20];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   const uint32_t last_nonce = max_nonce;
   const int thr_id = mythr->id;

   for ( int k = 0; k < 19; k++ )
      be32enc( &endiandata[k], pdata[k] );
   endiandata[19] = n;

   do {
      if ( algo_gate.hash( (char*) endiandata, (char*) vhash, thr_id ) )
      if unlikely( valid_hash( vhash, ptarget ) && !opt_benchmark )
      {
          be32enc( pdata+19, n );
          submit_solution( work, vhash, mythr );
      }
      endiandata[19] = ++n;
   } while ( n < last_nonce && !work_restart[thr_id].restart );
   *hashes_done = n - first_nonce;
   pdata[19] = n;
   return 0;
}

/* Every yespower/yescrypt variant shares one thread-local region, sized by the
 * variant (2 MB yescrypt to 16 MB yescryptr32), so one free serves all eight
 * registrations below. */
static void yespower_gate_thread_free( int thr_id )
{
   (void)thr_id;
   yespower_tls_free();
}

bool register_yespower_algo( algo_gate_t* gate )
{
  yespower_params.version = YESPOWER_1_0;

  if ( opt_param_n )  yespower_params.N = opt_param_n;
  else                yespower_params.N = 2048;

  if ( opt_param_r )  yespower_params.r = opt_param_r;
  else                yespower_params.r = 32;

  if ( opt_param_key )
  {
     yespower_params.pers = opt_param_key;
     yespower_params.perslen = strlen( opt_param_key );
  }
  else
  {
     yespower_params.pers    = NULL;
     yespower_params.perslen = 0;
  }

  applog( LOG_NOTICE,"Yespower parameters: N= %d, R= %d", yespower_params.N,
                                                           yespower_params.r );
  if ( yespower_params.pers )
     applog( LOG_NOTICE,"Key= \"%s\"\n", yespower_params.pers );

  gate->optimizations = SSE2_OPT | SHA256_OPT | NEON_OPT;
  gate->scanhash      = (void*)&scanhash_yespower;
  gate->miner_thread_free = (void*)&yespower_gate_thread_free;
#if (__SSE2__) || defined(__aarch64__)
  gate->hash          = (void*)&yespower_hash;
#else
  gate->hash          = (void*)&yespower_hash_ref;
#endif
  opt_target_factor = 65536.0;
  return yespower_gate_self_test();
};

bool register_yespowerr16_algo( algo_gate_t* gate )
{
  yespower_params.version = YESPOWER_1_0;
  yespower_params.N       = 4096;
  yespower_params.r       = 16;
  yespower_params.pers    = NULL;
  yespower_params.perslen = 0;
  gate->optimizations     = SSE2_OPT | SHA256_OPT | NEON_OPT;
  gate->scanhash          = (void*)&scanhash_yespower;
  gate->miner_thread_free = (void*)&yespower_gate_thread_free;
#if (__SSE2__) || defined(__aarch64__)
  gate->hash              = (void*)&yespower_hash;
#else
  gate->hash              = (void*)&yespower_hash_ref;
#endif
  opt_target_factor = 65536.0;
  return yespower_gate_self_test();
 };

// Legacy Yescrypt (yespower v0.5)

bool register_yescrypt_algo( algo_gate_t* gate )
{
   gate->optimizations = SSE2_OPT | SHA256_OPT | NEON_OPT;
   gate->scanhash   = (void*)&scanhash_yespower;
   gate->miner_thread_free = (void*)&yespower_gate_thread_free;
#if (__SSE2__) || defined(__aarch64__)
   gate->hash       = (void*)&yespower_hash;
#else
   gate->hash       = (void*)&yespower_hash_ref;
#endif
   yespower_params.version = YESPOWER_0_5;
   opt_target_factor = 65536.0;

   if ( opt_param_n )  yespower_params.N = opt_param_n;
   else                yespower_params.N = 2048;

   if ( opt_param_r )  yespower_params.r = opt_param_r;
   else                yespower_params.r = 8;

   if ( opt_param_key )
   {
     yespower_params.pers = opt_param_key;
     yespower_params.perslen = strlen( opt_param_key );
   }
   else
   {
     yespower_params.pers = NULL;
     yespower_params.perslen = 0;
   }

   applog( LOG_NOTICE,"Yescrypt parameters: N= %d, R= %d.",
                                      yespower_params.N, yespower_params.r );
   if ( yespower_params.pers )
     applog( LOG_NOTICE,"Key= \"%s\"\n", yespower_params.pers );

   return yespower_gate_self_test();
}


bool register_yescryptr8_algo( algo_gate_t* gate )
{
   gate->optimizations = SSE2_OPT | SHA256_OPT | NEON_OPT;
   gate->scanhash      = (void*)&scanhash_yespower;
   gate->miner_thread_free = (void*)&yespower_gate_thread_free;
#if (__SSE2__) || defined(__aarch64__)
   gate->hash          = (void*)&yespower_hash;
#else
   gate->hash          = (void*)&yespower_hash_ref;
#endif
   yespower_params.version = YESPOWER_0_5;
   yespower_params.N       = 2048;
   yespower_params.r       = 8;
   yespower_params.pers    = "Client Key";
   yespower_params.perslen = 10;
   opt_target_factor = 65536.0;
   return yespower_gate_self_test();
}

bool register_yescryptr16_algo( algo_gate_t* gate )
{
   gate->optimizations = SSE2_OPT | SHA256_OPT | NEON_OPT;
   gate->scanhash   = (void*)&scanhash_yespower;
   gate->miner_thread_free = (void*)&yespower_gate_thread_free;
#if (__SSE2__) || defined(__aarch64__)
   gate->hash          = (void*)&yespower_hash;
#else
   gate->hash          = (void*)&yespower_hash_ref;
#endif
   yespower_params.version = YESPOWER_0_5;
   yespower_params.N       = 4096;
   yespower_params.r       = 16;
   yespower_params.pers    = "Client Key";
   yespower_params.perslen = 10;
   opt_target_factor = 65536.0;
   return yespower_gate_self_test();
}

bool register_yescryptr32_algo( algo_gate_t* gate )
{
   gate->optimizations = SSE2_OPT | SHA256_OPT | NEON_OPT;
   gate->scanhash   = (void*)&scanhash_yespower;
   gate->miner_thread_free = (void*)&yespower_gate_thread_free;
#if (__SSE2__) || defined(__aarch64__)
   gate->hash          = (void*)&yespower_hash;
#else
   gate->hash          = (void*)&yespower_hash_ref;
#endif
   yespower_params.version = YESPOWER_0_5;
   yespower_params.N       = 4096;
   yespower_params.r       = 32;
   yespower_params.pers    = "WaviBanana";
   yespower_params.perslen = 10;
   opt_target_factor = 65536.0;
   return yespower_gate_self_test();
}

// POWER2B

bool register_power2b_algo( algo_gate_t* gate )
{
  yespower_params.version = YESPOWER_1_0;

  yespower_params.N = 2048;
  yespower_params.r = 32;
  yespower_params.pers = "Now I am become Death, the destroyer of worlds";
  yespower_params.perslen = 46;

  applog( LOG_NOTICE,"yespower-b2b parameters: N= %d, R= %d", yespower_params.N,
                                                           yespower_params.r );
  applog( LOG_NOTICE,"Key= \"%s\"", yespower_params.pers );
  applog( LOG_NOTICE,"Key length= %d\n", yespower_params.perslen );

  gate->optimizations = SSE2_OPT | AVX2_OPT | NEON_OPT;
  gate->scanhash      = (void*)&scanhash_yespower_b2b;
  gate->miner_thread_free = (void*)&yespower_gate_thread_free;
#if (__SSE2__) || defined(__aarch64__)
  gate->hash          = (void*)&yespower_b2b_hash;
#else
  gate->hash          = (void*)&yespower_b2b_hash_ref;
#endif
  opt_target_factor = 65536.0;
  return yespower_b2b_self_test();
};

// Generic yespower + blake2b
bool register_yespower_b2b_algo( algo_gate_t* gate )
{
  yespower_params.version = YESPOWER_1_0;

  if ( !( opt_param_n && opt_param_r ) )
  {
     applog(LOG_ERR,"Yespower-b2b N & R parameters are required");
     return false;
  }

  yespower_params.N = opt_param_n;
  yespower_params.r = opt_param_r;

  if ( opt_param_key )
  {
     yespower_params.pers = opt_param_key;
     yespower_params.perslen = strlen( opt_param_key );
  }
  else
  {
     yespower_params.pers    = NULL;
     yespower_params.perslen = 0;
  }

  applog( LOG_NOTICE,"Yespower-b2b parameters: N= %d, R= %d",
                       yespower_params.N, yespower_params.r );
  if ( yespower_params.pers )
  {
     applog( LOG_NOTICE,"Key= \"%s\"", yespower_params.pers );
     applog( LOG_NOTICE,"Key length= %d\n", yespower_params.perslen );
  }  

  gate->optimizations = SSE2_OPT | AVX2_OPT | NEON_OPT;
  gate->scanhash      = (void*)&scanhash_yespower_b2b;
  gate->miner_thread_free = (void*)&yespower_gate_thread_free;
#if (__SSE2__) || defined(__aarch64__)
  gate->hash          = (void*)&yespower_b2b_hash;
#else
  gate->hash          = (void*)&yespower_b2b_hash_ref;
#endif
  opt_target_factor = 65536.0;
  return yespower_b2b_self_test();
};

