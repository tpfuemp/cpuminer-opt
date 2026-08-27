#include "algo-gate-api.h"
#include "whirlpoolx2-kat.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "sph_whirlpool.h"

/* whirlpoolx2 -- CapStash (CAP). Consensus: CapStash-Core
 * src/primitives/block.cpp CBlockHeader::GetPoWHash().
 *
 *    Whirlpool512( 80-byte header )  ->  out[i] = wh[i] ^ wh[i+32]  (i < 32)
 *
 * compared as a little-endian uint256. "x2" is that 512->256 fold, not a second
 * pass.
 *
 * Two things differ from `whirlpoolx` and both fail silently, so do not copy
 * from whirlpoolx.c: the primitive is plain sph_whirlpool (ISO/IEC 10118-3),
 * NOT the sph_whirlpool1 that whirlpool.c and whirlpoolx.c call, and the fold
 * offset is 32, not 16. whirlpoolx2_self_test() asserts both.
 */

void whirlpoolx2_hash( void *state, const void *input )
{
   sph_whirlpool_context ctx;
   uint32_t _ALIGN(64) wh[16];
   uint32_t *out = (uint32_t*)state;

   sph_whirlpool_init( &ctx );
   sph_whirlpool( &ctx, input, 80 );
   sph_whirlpool_close( &ctx, wh );

   /* XOR is bytewise, so folding 32-bit words gives the same bytes as
    * out[i] = wh[i] ^ wh[i+32] without a byte cast. */
   for ( int i = 0; i < 8; i++ )
      out[i] = wh[i] ^ wh[i + 8];
}

/* The nonce is at bytes 76..79, so Whirlpool's first block is constant across a
 * scan; caching it halves the compressions per nonce. This is the path scanhash
 * runs, so the self-test covers it too. */
static void whirlpoolx2_hash_mid( void *state, const void *input,
                                  const sph_whirlpool_context *mid )
{
   sph_whirlpool_context ctx;
   uint32_t _ALIGN(64) wh[16];
   uint32_t *out = (uint32_t*)state;

   memcpy( &ctx, mid, sizeof ctx );
   sph_whirlpool( &ctx, (const unsigned char*)input + 64, 16 );
   sph_whirlpool_close( &ctx, wh );

   for ( int i = 0; i < 8; i++ )
      out[i] = wh[i] ^ wh[i + 8];
}

static void whirlpoolx2_midstate( sph_whirlpool_context *mid, const void *input )
{
   sph_whirlpool_init( mid );
   sph_whirlpool( mid, input, 64 );
}

const char *whirlpoolx2_self_test( void )
{
   uint32_t _ALIGN(64) dig[8];
   uint32_t _ALIGN(64) tgt[8];
   unsigned char hdr[80];

   memcpy( tgt, whirlpoolx2_kat_target, 32 );

   for ( size_t i = 0; i < WHIRLPOOLX2_NUM_KATS; i++ )
   {
      sph_whirlpool_context mid;

      whirlpoolx2_hash( dig, whirlpoolx2_kats[i].header );
      if ( memcmp( dig, whirlpoolx2_kats[i].digest, 32 ) )
         return whirlpoolx2_kats[i].name;

      /* Mined headers, so the digest must clear their own nBits. Checked with
       * the shipped comparator, which also pins opt_target_factor. */
      if ( !valid_hash( dig, tgt ) )
         return "genesis digest is above its own nBits target";

      whirlpoolx2_midstate( &mid, whirlpoolx2_kats[i].header );
      whirlpoolx2_hash_mid( dig, whirlpoolx2_kats[i].header, &mid );
      if ( memcmp( dig, whirlpoolx2_kats[i].digest, 32 ) )
         return "midstate path disagrees with the KAT";
   }

   /* Non-vacuity, one flip per Whirlpool block: byte 40 (merkle root, so it
    * also catches a stale midstate) and byte 76 (nonce). */
   for ( int pos = 40; pos <= 76; pos += 36 )
   {
      sph_whirlpool_context mid;

      memcpy( hdr, whirlpoolx2_kats[0].header, 80 );
      hdr[pos] ^= 0x01;

      whirlpoolx2_hash( dig, hdr );
      if ( !memcmp( dig, whirlpoolx2_kats[0].digest, 32 ) )
         return "non-vacuity (flipped header gave the same digest)";

      whirlpoolx2_midstate( &mid, hdr );
      whirlpoolx2_hash_mid( dig, hdr, &mid );
      if ( !memcmp( dig, whirlpoolx2_kats[0].digest, 32 ) )
         return "non-vacuity (midstate path ignored a header change)";
   }

   /* The KAT catches a wrong hash only if the KAT itself is right. These assert
    * the vectors discriminate both deltas, so regenerating whirlpoolx2-kat.h
    * with the wrong fold or primitive cannot yield a self-consistent build. */
   {
      sph_whirlpool_context ctx;
      uint32_t _ALIGN(64) wh[16];
      uint32_t _ALIGN(64) alt[8];

      sph_whirlpool_init( &ctx );
      sph_whirlpool( &ctx, whirlpoolx2_kats[0].header, 80 );
      sph_whirlpool_close( &ctx, wh );
      /* fold at 16 == whirlpoolx's offset */
      for ( int i = 0; i < 8; i++ ) alt[i] = wh[i] ^ wh[i + 4];
      if ( !memcmp( alt, whirlpoolx2_kats[0].digest, 32 ) )
         return "delta guard: the offset-16 fold matched (fold offset is 32)";

      sph_whirlpool1_init( &ctx );
      sph_whirlpool1( &ctx, whirlpoolx2_kats[0].header, 80 );
      sph_whirlpool1_close( &ctx, wh );
      for ( int i = 0; i < 8; i++ ) alt[i] = wh[i] ^ wh[i + 8];
      if ( !memcmp( alt, whirlpoolx2_kats[0].digest, 32 ) )
         return "delta guard: whirlpool1 matched (primitive is plain whirlpool)";
   }

   return NULL;
}

int scanhash_whirlpoolx2( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(64) endiandata[20];
   uint32_t _ALIGN(64) vhash[8];
   sph_whirlpool_context mid;
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce - 1;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;
   volatile uint8_t *restart = &( work_restart[thr_id].restart );

   for ( int i = 0; i < 19; i++ )
      be32enc( &endiandata[i], pdata[i] );

   whirlpoolx2_midstate( &mid, endiandata );

   do {
      be32enc( &endiandata[19], ++n );
      whirlpoolx2_hash_mid( vhash, endiandata, &mid );

      if ( unlikely( valid_hash( vhash, ptarget ) && !bench ) )
      {
         pdata[19] = n;
         submit_solution( work, vhash, mythr );
      }
   } while ( likely( n < max_nonce && !( *restart ) ) );

   *hashes_done = n - first_nonce + 1;
   pdata[19] = n;
   return 0;
}

bool register_whirlpoolx2_algo( algo_gate_t *gate )
{
   const char *failed = whirlpoolx2_self_test();
   if ( failed )
   {
      applog( LOG_ERR, "whirlpoolx2 self-test failed: %s", failed );
      return false;
   }

   applog( LOG_NOTICE, "whirlpoolx2 self-test PASSED (%d CapStash genesis "
                       "vectors under nBits 0x1d01fffe, midstate path included)",
                       WHIRLPOOLX2_NUM_KATS );

   gate->scanhash = (void*)&scanhash_whirlpoolx2;
   gate->hash     = (void*)&whirlpoolx2_hash;

   /* Table-driven scalar core, 1-way scan: nothing to claim. */
   gate->optimizations = EMPTY_SET;

   /* Compared directly against nBits as a little-endian uint256, no shift. */
   opt_target_factor = 1.0;

   return true;
}
