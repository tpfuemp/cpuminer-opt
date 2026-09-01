#include "rinhash-gate.h"
#include "rinhash-kat.h"
#include "algo/blake3/blake3.h"
#include "algo/argon2d/argon2d/argon2.h"
#include "algo/keccak/keccak-hash-4way.h"      // sha3_256_prepad32
#include <string.h>
#include <stdio.h>

/* m_cost is fixed for this algo, so one thread-local block serves every hash
 * instead of the library's per-call malloc. It must be passed via
 * allocate_cbk/free_cbk; the library only skips its own allocation if those are
 * set. aligned(64) because argon2's opt.c loads blocks with vector ops and ARM's
 * mm_malloc only guarantees 16.
 * -DRINHASH_NO_TLS_MEM uses the library's allocation instead. */
#define RIN_MEM_BYTES  ( (size_t)RINHASH_M_COST * 1024 )

#if !defined(RINHASH_NO_TLS_MEM)

static __thread uint8_t rin_memory[ RIN_MEM_BYTES ]
                        __attribute__ ((aligned (64)));

static int rin_allocate( uint8_t **memory, size_t bytes )
{
   if ( bytes > RIN_MEM_BYTES ) return -1;    /* never: m_cost is fixed */
   *memory = rin_memory;
   return 0;
}

static void rin_free( uint8_t *memory, size_t bytes )
{
   /* Static storage: nothing to release. The library zeroes the block itself
    * when ARGON2_FLAG_CLEAR_MEMORY is set, which the default flags do not. */
   (void)memory; (void)bytes;
}

#endif

void rinhash_hash( void *state, const void *input )
{
   uint8_t blake3_out[32] __attribute__ ((aligned (64)));
   uint8_t argon2_out[32] __attribute__ ((aligned (64)));
   blake3_hasher hasher;

   blake3_hasher_init( &hasher );
   blake3_hasher_update( &hasher, input, 80 );
   blake3_hasher_finalize( &hasher, blake3_out, 32 );

   argon2_context ctx;
   memset( &ctx, 0, sizeof ctx );
   ctx.out     = argon2_out;
   ctx.outlen  = 32;
   ctx.pwd     = blake3_out;
   ctx.pwdlen  = 32;
   ctx.salt    = (uint8_t*)RINHASH_SALT;
   ctx.saltlen = (uint32_t)( sizeof(RINHASH_SALT) - 1 );
   ctx.t_cost  = RINHASH_T_COST;
   ctx.m_cost  = RINHASH_M_COST;
   ctx.lanes   = RINHASH_LANES;
   ctx.threads = RINHASH_LANES;
   ctx.version = ARGON2_VERSION_13;
   ctx.flags   = ARGON2_DEFAULT_FLAGS;
#if !defined(RINHASH_NO_TLS_MEM)
   ctx.allocate_cbk = &rin_allocate;
   ctx.free_cbk     = &rin_free;
#endif

   if ( argon2d_ctx( &ctx ) != ARGON2_OK )
   {
      memset( state, 0xff, 32 );          // never submittable
      return;
   }

   sha3_256_prepad32( state, argon2_out );
}

/* Digest and target are raw little-endian 256-bit values, so valid_hash() does
 * not apply -- it assumes the usual uint32[8] host-order layout. */
static inline int rin_hash_le_target( const uint8_t *h, const uint32_t *target )
{
   const uint8_t *t = (const uint8_t*)target;
   for ( int i = 31; i >= 0; i-- )
   {
      if ( h[i] < t[i] ) return 1;
      if ( h[i] > t[i] ) return 0;
   }
   return 1;
}

int scanhash_rinhash( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t edata[20] __attribute__ ((aligned (64)));
   uint8_t  hash[32]  __attribute__ ((aligned (64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;

   // BLAKE3 hashes the serialized header, so swap the work data words first;
   // the nonce then goes into the swapped buffer as a host word.
   v128_bswap32_80( edata, pdata );

   do
   {
      edata[19] = n;
      rinhash_hash( hash, edata );
      if ( unlikely( rin_hash_le_target( hash, ptarget ) && !bench ) )
      {
         pdata[19] = bswap_32( n );
         submit_solution( work, hash, mythr );
      }
      n++;
   } while ( n < last_nonce && !work_restart[thr_id].restart );

   *hashes_done = n - first_nonce;
   pdata[19] = bswap_32( n );
   return 0;
}

/* Startup gate: real mainnet headers, each asserted twice -- digest exact, and
 * under that block's own nBits target. Either assertion alone is weaker. */
static bool rinhash_self_test( void )
{
   uint8_t got[32];
   int pass = 0;

   for ( unsigned k = 0; k < RINHASH_KAT_COUNT; k++ )
   {
      rinhash_hash( got, rinhash_kat[k].header );
      if ( memcmp( got, rinhash_kat[k].digest, 32 ) != 0 )
      {
         applog( LOG_ERR, "rinhash KAT %u (height %u): digest mismatch",
                 k, rinhash_kat[k].height );
         return false;
      }
      if ( !rin_hash_le_target( got, (const uint32_t*)rinhash_kat[k].target ) )
      {
         applog( LOG_ERR, "rinhash KAT %u (height %u): digest over target",
                 k, rinhash_kat[k].height );
         return false;
      }
      pass++;
   }

   /* Non-vacuity: one flipped nonce bit must change the digest. */
   uint8_t bad[80];
   memcpy( bad, rinhash_kat[0].header, 80 );
   bad[79] ^= 1;
   rinhash_hash( got, bad );
   if ( memcmp( got, rinhash_kat[0].digest, 32 ) == 0 )
   {
      applog( LOG_ERR, "rinhash KAT is vacuous: altered header gave the same digest" );
      return false;
   }

   applog( LOG_NOTICE, "rinhash self-test PASSED (%d real mainnet headers, "
           "genesis to height %u, digest and target)", pass,
           rinhash_kat[RINHASH_KAT_COUNT-1].height );
   return true;
}

bool register_rinhash_algo( algo_gate_t* gate )
{
   if ( !rinhash_self_test() ) return false;

   gate->scanhash      = (void*)&scanhash_rinhash;
   gate->hash          = (void*)&rinhash_hash;
   gate->optimizations = SSE2_OPT | AVX2_OPT | AVX512_OPT | NEON_OPT;
   opt_target_factor   = 1.0;
   return true;
}
