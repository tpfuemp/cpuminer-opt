#include "curvehash-gate.h"
#include "curvehash-kat.h"
#include "algo/sha/sha256-hash.h"
#include "secp256k1/include/secp256k1.h"

#include <string.h>

/* curvehash (Pulsar, PLSR) -- 8 rounds of "treat the SHA-256 digest as a
 * secp256k1 private key and hash the uncompressed public key". Consensus is
 * Pulsar's src/pulsar.cpp (Pulsar / GetCurvehashHash).
 *
 * ~2 kH/s/thread is correct, not a bug: the 8 scalar multiplications are the
 * whole cost. Coverage, not competitive mining -- see docs/algorithms/. */

/* Shared read-only. pubkey_create takes a const ctx and does not mutate it
 * (only context_randomize does), so one for all threads is safe, and avoids
 * duplicating the runtime-built ecmult_gen table per thread. */
static secp256k1_context *curvehash_ctx = NULL;

bool curvehash_hash( void *output, const void *input )
{
   secp256k1_pubkey pubkey;
   unsigned char pub[65];
   size_t publen = 65;
   unsigned char *phash = (unsigned char*)output;

   sha256_full( phash, input, 80 );

   for ( int round = 0; round < 8; round++ )
   {
      /* Consensus asserts this is 1; phash == 0 or >= n is ~2^-128. Report it
       * so the caller skips the nonce, never fabricate a digest. */
      if ( unlikely( !secp256k1_ec_pubkey_create( curvehash_ctx, &pubkey,
                                                  phash ) ) )
         return false;

      secp256k1_ec_pubkey_serialize( curvehash_ctx, pub, &publen, &pubkey,
                                     SECP256K1_EC_UNCOMPRESSED );
      sha256_full( phash, pub, 65 );
   }
   return true;
}

const char *curvehash_self_test( void )
{
   unsigned char out[32], hdr[80];

   for ( size_t i = 0; i < CURVEHASH_NUM_KATS; i++ )
   {
      if ( !curvehash_hash( out, curvehash_kats[i].header ) )
         return curvehash_kats[i].name;
      if ( memcmp( out, curvehash_kats[i].digest, 32 ) )
         return curvehash_kats[i].name;
   }

   /* Non-vacuity: without this, a KAT that hashed a constant would pass. */
   memcpy( hdr, curvehash_kats[0].header, 80 );
   hdr[40] ^= 0x01;
   if ( !curvehash_hash( out, hdr ) )
      return "non-vacuity (unexpected invalid seckey)";
   if ( !memcmp( out, curvehash_kats[0].digest, 32 ) )
      return "non-vacuity (flipped header gave the same digest)";

   return NULL;
}

int scanhash_curvehash( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(64) vhash[8];
   uint32_t _ALIGN(64) edata[20];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;

   /* Yields the LE wire header: work->data is stored word-swapped relative to
    * the wire (std_build_block_header), and sha256_full() hashes plain bytes.
    * Looks like a double swap, is not -- do not "fix" it. */
   v128_bswap32_80( edata, pdata );

   do
   {
      edata[19] = n;
      if ( likely( curvehash_hash( vhash, edata ) ) )
      if ( unlikely( valid_hash( vhash, ptarget ) && !bench ) )
      {
         be32enc( &pdata[19], n );
         submit_solution( work, vhash, mythr );
      }
      n++;
   } while ( likely( n < last_nonce && !work_restart[thr_id].restart ) );

   *hashes_done = n - first_nonce;
   pdata[19] = n;
   return 0;
}

bool register_curvehash_algo( algo_gate_t *gate )
{
   if ( !curvehash_ctx )
      curvehash_ctx = secp256k1_context_create( SECP256K1_CONTEXT_SIGN );
   if ( !curvehash_ctx )
   {
      applog( LOG_ERR, "curvehash: could not create a secp256k1 context" );
      return false;
   }

   const char *failed = curvehash_self_test();
   if ( failed )
   {
      applog( LOG_ERR, "curvehash self-test failed: %s", failed );
      return false;
   }

   gate->scanhash = (void*)&scanhash_curvehash;

   /* Nothing hand-vectorized here; sha256_full picks SHA-NI / ARMv8 SHA2 at
    * compile time and is ~1% of a hash, so nothing is claimed. */
   gate->optimizations = SSE2_OPT | NEON_OPT;

   /* Plain 256-bit output. Confirmed by two mainnet blocks whose digests sit
    * under the nBits target read as a LE uint256, as valid_hash does. */
   opt_target_factor = 1.0;

   return true;
}
