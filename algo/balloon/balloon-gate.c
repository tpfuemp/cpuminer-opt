#include "algo-gate-api.h"
#include "balloon.h"

/* Balloon (Mateable, MTBC).
 *
 * Stock header handling: 80 bytes, big-endian words, nonce at word 19, so the
 * default build_extraheader applies. The digest goes to valid_hash() as raw
 * little-endian uint32[8] with no byte reversal — confirmed against a share
 * the pool accepted, see docs/algorithms/balloon.md.                        */

int scanhash_balloon( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(64) hash[8];
   uint32_t _ALIGN(64) edata[20];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const int thr_id = mythr->id;
   uint32_t n = first_nonce;
   volatile uint8_t *restart = &( work_restart[thr_id].restart );
   const bool bench = opt_benchmark;

   /* 224 KiB per thread, allocated on the first call and kept. It also holds
    * the index table, which is why it must never be shared between threads. */
   balloon_ctx *ctx = balloon_thread_ctx();
   if ( unlikely( !ctx ) )
   {
      applog( LOG_ERR, "balloon thr%d: could not allocate %u KiB of scratch",
              thr_id, (unsigned)( sizeof(balloon_ctx) >> 10 ) );
      return -1;
   }

   for ( int i = 0; i < 19; i++ )
      be32enc( &edata[i], pdata[i] );

   do
   {
      be32enc( &edata[19], n );
      balloon_hash_header( ctx, edata, hash );

      if ( unlikely( valid_hash( hash, ptarget ) && !bench ) )
      {
         pdata[19] = n;
         submit_solution( work, hash, mythr );
      }
      n++;
   } while ( n < max_nonce && !(*restart) );

   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

bool register_balloon_algo( algo_gate_t *gate )
{
   const char *failed = balloon_self_test();
   if ( failed )
   {
      applog( LOG_ERR, "balloon self-test failed: %s", failed );
      return false;
   }

   gate->scanhash = (void*)&scanhash_balloon;

   /* Nothing here is hand-vectorized. Whether SHA-NI or ARMv8 SHA2 is used is
    * decided inside sha256_full at compile time, so it is not claimed here. */
   gate->optimizations = SSE2_OPT | NEON_OPT;

   /* Measured, not assumed: a pool-accepted share was found at nonce 128454
    * against an expected 429497 at factor 1. Factor 256 predicts 1678.      */
   opt_target_factor = 1.0;

   return true;
}
