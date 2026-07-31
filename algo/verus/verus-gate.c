// VerusHash 2.2 gate for cpuminer-opt.
//
// The hash chain itself lives in the vendored upstream sources (haraka.c,
// verus_clhash.cpp); this file is the cpuminer-opt integration: preimage
// assembly, the per-job cache, the per-nonce loop, and the self-test.
//
// Chain functions are transcribed from the reference verus/verusscan.cpp
// (branch Verus2.2 @ e28e183, lines 50-155) rather than reimplemented -- the
// arithmetic is consensus-critical.

#include "verus-gate.h"
#include "verus-simd.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* Verus and Equihash 200/9 share the wire format exactly -- 140-byte header,
 * 32-byte nonce at offset 108, same submit params and 1344-byte solution -- so
 * reuse rather than duplicate. */
#include "algo/equihash/equihash-gate.h"

/* Needs hardware AES + carryless multiply. verus-simd.h decides and pulls the
 * matching intrinsic header, so keep those includes inside the guard or targets
 * without either fail here instead of compiling out. */
#if defined(VERUS_HAVE_SIMD)

#include "haraka.h"
#include "haraka_portable.h"
#include "verus_clhash.h"
#include "verus-kat.h"

// ---------------------------------------------------------------------------
// Per-thread state.
//
// The reference malloc/frees a 9856-byte key per scanhash call and re-runs the
// 46+276 Haraka prologue every time. Both are hoisted here: the buffer is
// thread-local and persistent, and the prologue re-runs only when the
// job-constant first 1472 bytes of the preimage actually change.
// ---------------------------------------------------------------------------
typedef struct {
   u128     key[VERUS_KEY_SIZE128 + VERUS_SCRATCH_U128];  /* 616 u128 = 9856 B */
   uint8_t  half[64];                  /* VerusHashHalf output (state+15+pad)  */
   uint8_t  prefix[VERUS_PREIMAGE_MAX];/* cache tag: the job-constant bytes    */
   int      prefix_len;
   bool     warned_no_solution;
   bool     valid;
} verus_ctx_t;

static __thread verus_ctx_t *verus_ctx = NULL;

static verus_ctx_t *verus_get_ctx( void )
{
   if ( unlikely( verus_ctx == NULL ) )
   {
      /* 64-byte aligned: the key is indexed as u128 and read by aligned loads */
      if ( posix_memalign( (void**)&verus_ctx, 64, sizeof(verus_ctx_t) ) != 0 )
         return NULL;
      memset( verus_ctx, 0, sizeof(verus_ctx_t) );
   }
   return verus_ctx;
}

/* CBlockHeader::ClearNonCanonicalData(): merge-mined chains must all validate
 * the same PoW, so chain-specific fields are zeroed and anything the miner
 * varies moves into the 15 solution bytes. nVersion and nTime stay -- they are
 * shared across the merged blocks. The self-test runs this same function over a
 * real block, which is what pins these offsets. */
static void verus_clear_noncanonical( uint8_t *pre )
{
   memset( pre + 4, 0, 96 );                    /* prevhash, merkle, saplingroot */
   memset( pre + 104, 0, 4 );                   /* nBits  */
   memset( pre + 108, 0, 32 );                  /* nNonce */
   memset( pre + VERUS_BASE_SIZE + 8, 0, 64 );  /* hashPrev/BlockMMRRoot */
}

// ---------------------------------------------------------------------------
// Chain functions (transcribed from verusscan.cpp)
// ---------------------------------------------------------------------------
static void GenNewCLKey( unsigned char *seedBytes32, u128 *keyback )
{
   const int n256blks    = VERUS_KEY_SIZE >> 5;     /* 276 */
   const int nbytesExtra = VERUS_KEY_SIZE & 0x1f;   /* 0   */
   unsigned char *pkey = (unsigned char*)keyback;
   unsigned char *psrc = seedBytes32;

   for ( int i = 0; i < n256blks; i++ )
   {
      haraka256( pkey, psrc );
      psrc  = pkey;
      pkey += 32;
   }
   if ( nbytesExtra )
   {
      unsigned char buf[32];
      haraka256( buf, psrc );
      memcpy( pkey, buf, nbytesExtra );
   }
}

/* Undo the <=64 mutated key slots from the journal. Reverse order matters:
 * indices can repeat across iterations, so the oldest saved value must land
 * last. Within an iteration prandex is restored before prand, mirroring the
 * algorithm's own write order when both indices collide. */
static void FixKey( uint32_t *fixrand, uint32_t *fixrandex, u128 *keyback,
                    u128 *g_prand, u128 *g_prandex )
{
   for ( int i = 31; i > -1; i-- )
   {
      keyback[ fixrandex[i] ] = g_prandex[i];
      keyback[ fixrand[i]   ] = g_prand[i];
   }
}

static void VerusHashHalf( void *result2, unsigned char *data, int len )
{
   unsigned char _ALIGN(32) buf1[64] = {0}, buf2[64];
   unsigned char *curBuf = buf1, *result = buf2, *tmp;
   int curPos = 0;

   load_constants();
   load_constants_port();

   for ( int pos = 0; pos < len; )
   {
      int room = 32 - curPos;
      if ( len - pos >= room )
      {
         memcpy( curBuf + 32 + curPos, data + pos, room );
         haraka512( result, curBuf );
         tmp = curBuf; curBuf = result; result = tmp;
         pos += room; curPos = 0;
      }
      else
      {
         memcpy( curBuf + 32 + curPos, data + pos, len - pos );
         curPos += len - pos;
         pos = len;
      }
   }
   /* FillExtra, hand-unrolled: pad[0..15] = state[0..15], pad[16] = state[0].
    * Non-zero padding so the unused bytes are not foreknown. */
   memcpy( curBuf + 47, curBuf, 16 );
   memcpy( curBuf + 63, curBuf, 1 );
   memcpy( result2, curBuf, 64 );
}

/* One nonce. `curBuf` is a scratch copy of the 64-byte half state; `hash`
 * receives only bytes 28..31 (see verushash_full for the whole digest). */
static inline void Verus2hash( unsigned char *hash, unsigned char *curBuf,
                               unsigned char *nonce, u128 *data_key,
                               uint32_t *fixrand, uint32_t *fixrandex,
                               u128 *g_prand, u128 *g_prandex,
                               const bool full )
{
   /* not `static const` as upstream has it: _mm_setr_epi8 is not a constant
    * initializer in C (it is in C++), and this file is C. GCC materialises
    * these as constants anyway. */
   const __m128i shuf1 = _mm_setr_epi8( 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0 );
   const __m128i shuf2 = _mm_setr_epi8( 1,2,3,4,5,6,7,0,1,2,3,4,5,6,7,0 );

   const __m128i fill1 = _mm_shuffle_epi8( _mm_load_si128( (u128*)curBuf ), shuf1 );
   const unsigned char ch = curBuf[0];
   _mm_store_si128( (u128*)( &curBuf[32 + 16] ), fill1 );
   curBuf[32 + 15] = ch;

   memcpy( curBuf + 32, nonce, VERUS_NONCE_SPACE );

   uint64_t intermediate = verusclhashv2_2( data_key, curBuf, 511,
                                            fixrand, fixrandex,
                                            g_prand, g_prandex );

   const __m128i fill2 =
      _mm_shuffle_epi8( _mm_loadl_epi64( (u128*)&intermediate ), shuf2 );
   _mm_store_si128( (u128*)( &curBuf[32 + 16] ), fill2 );
   curBuf[32 + 15] = *( (unsigned char*)&intermediate );

   /* Round constants come from the MUTATED key at a data-dependent offset --
    * what makes VerusHash 2.x hostile to fixed-function hardware.
    * haraka512_keyed is truncated to out[28..31], enough for the target test and
    * the reference's main per-nonce saving; candidates re-do it in software to
    * get all 32 bytes. `full` is literal at both call sites, so this folds. */
   if ( full )
      haraka512_port_keyed( hash, curBuf, data_key + ( intermediate & 511 ) );
   else
      haraka512_keyed( hash, curBuf, data_key + ( intermediate & 511 ) );

   FixKey( fixrand, fixrandex, data_key, g_prand, g_prandex );
}

// ---------------------------------------------------------------------------
// Full 1487-byte-preimage hash (gate->hash; also the self-test entry).
// Produces the FULL 32-byte digest by using the portable keyed Haraka, which
// unlike the AES-NI one is not truncated. Only for candidates and tests --
// the inner loop uses the truncated form.
// ---------------------------------------------------------------------------
int verushash_full( void *output, const void *preimage, int pre_len )
{
   verus_ctx_t *ctx = verus_get_ctx();
   if ( ctx == NULL ) return 0;

   uint8_t _ALIGN(32) curBuf[64];
   uint32_t fixrand[32], fixrandex[32];
   u128 *g_prand   = ctx->key + VERUS_KEY_SIZE128;
   u128 *g_prandex = ctx->key + VERUS_KEY_SIZE128 + 32;
   const uint8_t *pre = (const uint8_t*)preimage;
   const int half_len = pre_len - VERUS_NONCE_SPACE;

   VerusHashHalf( ctx->half, (unsigned char*)pre, half_len );
   GenNewCLKey( ctx->half, ctx->key );
   ctx->valid = false;                 /* this path bypasses the job cache */

   memcpy( curBuf, ctx->half, 64 );
   /* the 15 tail bytes of the preimage are the nonce space */
   Verus2hash( (unsigned char*)output, curBuf,
               (unsigned char*)pre + half_len, ctx->key,
               fixrand, fixrandex, g_prand, g_prandex, true );
   return 1;
}

// ---------------------------------------------------------------------------
// Self-test: real-block KAT + two free invariants.
//
// verus-kat.h holds a mainnet block exactly as the chain serializes it, and its
// published hash. Reproducing that hash means the whole chain, the canonical
// clearing and the nonce placement agree with consensus -- not merely with a
// vector this code produced. Only the two stage checkpoints are ours, and they
// exist so a failure names the stage instead of just the digest.
// ---------------------------------------------------------------------------
static uint64_t verus_fnv1a( const void *p, size_t n, uint64_t h )
{
   for ( size_t i = 0; i < n; i++ )
   {
      h ^= ((const uint8_t*)p)[i];
      h *= 1099511628211ULL;
   }
   return h;
}

bool verus_self_test( void )
{
   verus_ctx_t *ctx = verus_get_ctx();
   if ( ctx == NULL )
   {
      applog( LOG_ERR, "VerusHash: context allocation failed" );
      return false;
   }

   uint8_t _ALIGN(32) pre[VERUS_KAT_PREIMAGE];
   uint32_t fixrand[32], fixrandex[32];
   u128 *g_prand   = ctx->key + VERUS_KEY_SIZE128;
   u128 *g_prandex = ctx->key + VERUS_KEY_SIZE128 + 32;

   memcpy( pre, verus_kat_block, VERUS_KAT_PREIMAGE );
   verus_clear_noncanonical( pre );     /* solution version 8, so PBaaS */
   VerusHashHalf( ctx->half, pre, VERUS_KAT_PREIMAGE - VERUS_NONCE_SPACE );

   if ( memcmp( ctx->half, verus_kat_half, 32 ) != 0 )
   {
      applog( LOG_ERR, "VerusHash self-test FAILED: VerusHashHalf mismatch" );
      return false;
   }

   GenNewCLKey( ctx->half, ctx->key );
   const uint64_t key_fnv =
      verus_fnv1a( ctx->key, VERUS_KEY_SIZE, 1469598103934665603ULL );
   if ( key_fnv != VERUS_KAT_KEY_FNV )
   {
      applog( LOG_ERR, "VerusHash self-test FAILED: GenNewCLKey mismatch "
                       "(%016llx want %016llx)", (unsigned long long)key_fnv,
              (unsigned long long)VERUS_KAT_KEY_FNV );
      return false;
   }

   /* The block's own nonce is already in place, so the digest must come out as
    * its published hash. Both keyed-Haraka paths are exercised: the inner loop's
    * truncated one, then the candidate path's full one. */
   uint8_t *nonce = pre + VERUS_KAT_PREIMAGE - VERUS_NONCE_SPACE;
   uint8_t _ALIGN(32) curBuf[64];
   uint8_t hash[32] = {0};

   memcpy( curBuf, ctx->half, 64 );
   Verus2hash( hash, curBuf, nonce, ctx->key,
               fixrand, fixrandex, g_prand, g_prandex, false );

   if ( memcmp( hash + 28, verus_kat_hash + 28, 4 ) != 0 )
   {
      uint32_t got, want;
      memcpy( &got, hash + 28, 4 ); memcpy( &want, verus_kat_hash + 28, 4 );
      applog( LOG_ERR, "VerusHash self-test FAILED: block %d vhash[7] %08x "
                       "want %08x", VERUS_KAT_HEIGHT, got, want );
      return false;
   }
   /* invariant: the AES-NI keyed Haraka writes ONLY bytes 28..31 */
   for ( int i = 0; i < 28; i++ )
      if ( hash[i] != 0 )
      {
         applog( LOG_ERR, "VerusHash self-test FAILED: truncated Haraka wrote "
                          "byte %d -- inner loop assumption broken", i );
         return false;
      }
   /* invariant: FixKey must restore the key to pristine after every hash */
   if ( verus_fnv1a( ctx->key, VERUS_KEY_SIZE, 1469598103934665603ULL )
        != VERUS_KAT_KEY_FNV )
   {
      applog( LOG_ERR, "VerusHash self-test FAILED: FixKey did not restore the "
                       "key (journal order bug?)" );
      return false;
   }

   memcpy( curBuf, ctx->half, 64 );
   Verus2hash( hash, curBuf, nonce, ctx->key,
               fixrand, fixrandex, g_prand, g_prandex, true );

   if ( memcmp( hash, verus_kat_hash, 32 ) != 0 )
   {
      applog( LOG_ERR, "VerusHash self-test FAILED: block %d digest mismatch",
              VERUS_KAT_HEIGHT );
      return false;
   }

   ctx->valid = false;
   applog( LOG_NOTICE, "VerusHash 2.2 self-test PASSED (mainnet block %d hash "
                       "reproduced on both keyed-Haraka paths)",
           VERUS_KAT_HEIGHT );
   return true;
}

// ---------------------------------------------------------------------------
// scanhash
//
// The 1344-byte solution is supplied by the pool as mining.notify param[8];
// the miner varies only its last 15 bytes. Without one this refuses to mine
// rather than hashing a wrong preimage.
// ---------------------------------------------------------------------------
int scanhash_verus( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t *pdata   = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[ VRS_NONCE_INDEX ];
   const uint32_t targ32 = ptarget[7];
   const int thr_id = mythr->id;
   volatile uint8_t *restart = &( work_restart[thr_id].restart );
   const bool bench = opt_benchmark;

   verus_ctx_t *ctx = verus_get_ctx();
   if ( ctx == NULL ) { *hashes_done = 0; return 0; }

   /* The solution comes from the pool (mining.notify param[8]), already padded
    * to the size upstream requires. Its length is NOT fixed -- pool.verus.io
    * sends 281 bytes, padded to 320. In benchmark mode substitute a
    * deterministic one so --benchmark measures the real hash; otherwise refuse
    * to mine rather than hash a wrong preimage. */
   const uint8_t *solution = work->equihash_solution;
   int sol_size = (int)work->equihash_solution_len;

   if ( solution == NULL || sol_size < 253 || sol_size > VERUS_SOLUTION_MAX )
   {
      if ( !bench )
      {
         if ( !ctx->warned_no_solution )      /* once per thread, not per call */
         {
            applog( LOG_WARNING, "VerusHash: no usable pool solution in work" );
            ctx->warned_no_solution = true;
         }
         *hashes_done = 0;
         return 0;
      }
      /* the KAT block's own solution: real descriptor, so --benchmark measures
       * the PBaaS path real jobs take */
      solution = verus_kat_block + VERUS_BASE_SIZE;
      sol_size = VERUS_KAT_PREIMAGE - VERUS_BASE_SIZE;
   }
   ctx->warned_no_solution = false;

   /* base+solution must be 15 (mod 32): one partial Haraka block with 15 free
    * bytes. If it is not, the solution was not padded and hashing it would
    * silently produce a preimage no pool will accept. */
   const int pre_len = VERUS_BASE_SIZE + sol_size;
   if ( ( pre_len % 32 ) != VERUS_NONCE_SPACE )
   {
      if ( !ctx->warned_no_solution )
      {
         applog( LOG_ERR, "VerusHash: solution size %d gives preimage %d "
                          "(%d mod 32, need %d) -- not padded",
                 sol_size, pre_len, pre_len % 32, VERUS_NONCE_SPACE );
         ctx->warned_no_solution = true;
      }
      *hashes_done = 0;
      return 0;
   }
   const int half_len = pre_len - VERUS_NONCE_SPACE;

   uint8_t _ALIGN(64) full[VERUS_PREIMAGE_MAX] = {0};
   uint8_t *sol_data = full + VERUS_HEADER_SIZE;
   uint8_t nonceSpace[VERUS_NONCE_SPACE] = {0};

   memcpy( full, pdata, VERUS_HEADER_SIZE );
   /* CompactSize, always the 3-byte form so the base stays 143 as upstream's
    * HEADER_BASESIZE assumes (hence the sol_size >= 253 check above). */
   sol_data[0] = 0xfd;
   sol_data[1] = (uint8_t)( sol_size & 0xff );
   sol_data[2] = (uint8_t)( sol_size >> 8 );
   memcpy( sol_data + 3, solution, sol_size );

   const bool pbaas = ( solution[0] >= 7 && solution[5] > 0 );
   if ( pbaas )
   {
      verus_clear_noncanonical( full );
      memcpy( nonceSpace,     &pdata[27], 7 );   /* pool extranonce1        */
      memcpy( nonceSpace + 7, &pdata[VRS_NONCESPACE_INDEX], 4 );
   }

   /* Job cache: re-run the Haraka prologue only when the job-constant bytes
    * actually change. */
   if ( !ctx->valid || ctx->prefix_len != half_len
        || memcmp( ctx->prefix, full, half_len ) != 0 )
   {
      memcpy( ctx->prefix, full, half_len );
      ctx->prefix_len = half_len;
      VerusHashHalf( ctx->half, full, half_len );
      GenNewCLKey( ctx->half, ctx->key );
      ctx->valid = true;
   }

   uint32_t fixrand[32], fixrandex[32];
   u128 *g_prand   = ctx->key + VERUS_KEY_SIZE128;
   u128 *g_prandex = ctx->key + VERUS_KEY_SIZE128 + 32;
   uint32_t n = first_nonce;

   do
   {
      uint8_t _ALIGN(32) curBuf[64];
      uint8_t hash[32] = {0};

      memcpy( curBuf, ctx->half, 64 );
      nonceSpace[11] = (uint8_t)( n       ); nonceSpace[12] = (uint8_t)( n >>  8 );
      nonceSpace[13] = (uint8_t)( n >> 16 ); nonceSpace[14] = (uint8_t)( n >> 24 );

      Verus2hash( hash, curBuf, nonceSpace, ctx->key,
                  fixrand, fixrandex, g_prand, g_prandex, false );

      /* Only hash[28..31] is written by the truncated keyed Haraka, so this is
       * the whole target test the reference does. A candidate is re-hashed in
       * full below so the submitted digest and the share-diff stats are real. */
      if ( unlikely( ((uint32_t*)hash)[7] <= targ32 && !bench ) )
      {
         uint8_t _ALIGN(64) fullhash[32];
         memcpy( full + half_len, nonceSpace, VERUS_NONCE_SPACE );
         verushash_full( fullhash, full, pre_len );
         ctx->valid = false;      /* verushash_full clobbered the cache */

         if ( valid_hash( (uint32_t*)fullhash, ptarget ) )
         {
            /* the pool needs the 15 nonce bytes inside the solution it gets back */
            memcpy( work->equihash_solution + sol_size - VERUS_NONCE_SPACE,
                    nonceSpace, VERUS_NONCE_SPACE );

            /* Submit the header exactly as hashed: in PBaaS mode a zeroed
             * nNonce, as upstream sends, the pool taking the real nonce from
             * the solution tail. Pools reject a non-zero one. Restore after --
             * nNonce also holds extranonce1 and the framework's range counter,
             * and submit_work deep-copies before returning. */
            uint32_t saved[8];
            memcpy( saved, pdata + 27, sizeof saved );
            if ( pbaas ) memset( pdata + 27, 0, sizeof saved );
            else         pdata[ VRS_NONCE_INDEX ] = n;

            submit_solution( work, fullhash, mythr );

            memcpy( pdata + 27, saved, sizeof saved );
            pdata[ VRS_NONCE_INDEX ] = n;
         }
      }
      n++;
   } while ( n < max_nonce && !(*restart) );

   pdata[ VRS_NONCE_INDEX ] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#else   /* no hardware AES+CLMUL: stubs so the tree still builds */

int verushash_full( void *output, const void *preimage, int pre_len )
{ (void)output; (void)preimage; (void)pre_len; return 0; }

int scanhash_verus( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr )
{ (void)work; (void)max_nonce; (void)mythr; *hashes_done = 0; return 0; }

bool verus_self_test( void ) { return false; }

#endif  /* VERUS_HAVE_SIMD */

bool register_verus_algo( algo_gate_t *gate )
{
#if !defined(VERUS_HAVE_SIMD)
   applog( LOG_ERR, "VerusHash requires hardware AES and carryless multiply; "
                    "rebuild with -march=native (x86: -maes -mpclmul, "
                    "aarch64: -march=armv8-a+crypto)" );
   (void)gate;
   return false;
#else
   if ( !verus_self_test() )
   {
      applog( LOG_ERR, "VerusHash self-test failed" );
      return false;
   }
   gate->scanhash              = (void*)&scanhash_verus;
   gate->hash                  = (void*)&verushash_full;
   gate->build_extraheader     = (void*)&equihash_build_extraheader;
   gate->build_stratum_request = (void*)&equihash_build_stratum_request;
   gate->get_work_data_size    = (void*)&equihash_get_work_data_size;
   gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | NEON_OPT;
   gate->ntime_index   = VRS_NTIME_INDEX;
   gate->nbits_index   = VRS_NBITS_INDEX;
   gate->nonce_index   = VRS_NONCE_INDEX;
   gate->work_cmp_size = VRS_WORK_CMP_SIZE;
   /* Verus's target arrives as the exact 32 bytes via mining.set_target and is
    * used verbatim (stratum_gen_work), so opt_target_factor does NOT affect
    * share validity here -- only the difficulty numbers in the log and API.
    * Verus's own convention uses a 0x0f0f0f numerator rather than ZCash's
    * 0xffff0000, so the displayed diff will read in internal (diff1 = 2^32)
    * units until this is calibrated against a live pool's reported share diff.
    * Deliberately not derived on paper: the same algebra fails to reproduce the
    * pool-validated EQH_DIFF_SCALE, so it needs one measurement, not a guess. */
   opt_target_factor   = 1.0;
   return true;
#endif
}
