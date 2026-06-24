// Copyright (c) 2012-2013 The Cryptonote developers
// Portions Copyright (c) 2018 The Monero developers
// Portions Copyright (c) 2018 The TurtleCoin Developers
// Distributed under the MIT/X11 software license.
//
// GhostRider CryptoNight (variant 1) core, parameterized for the six GR
// variants. Two interchangeable back ends, selected at compile time:
//   - __AES__ builds: hardware AES-NI (_mm_aesenc_si128) + __m128i scratchpad.
//   - otherwise:      portable table soft-AES (aesb.c) reference.
// Both share the keccak-based init/finalize (crypto/hash.c) and are validated
// against the same known-answer vectors. See cryptonight.h for the per-variant
// parameter table.

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(__AES__)
#include <immintrin.h>
#endif

#include "cryptonight.h"
#include "../../malloc-huge.h"
#if defined(__linux__)
#include <sys/mman.h>
#endif
#include "cryptonote/crypto/oaes_lib.h"
#include "cryptonote/crypto/c_keccak.h"
#include "cryptonote/crypto/c_groestl.h"
#include "cryptonote/crypto/c_blake256.h"
#include "cryptonote/crypto/c_jh.h"
#include "cryptonote/crypto/c_skein.h"
#include "cryptonote/crypto/int-util.h"
#include "cryptonote/crypto/hash-ops.h"

#define AES_BLOCK_SIZE  16
#define AES_KEY_SIZE    32
#define INIT_SIZE_BLK   8
#define INIT_SIZE_BYTE  (INIT_SIZE_BLK * AES_BLOCK_SIZE)   // 128
#define CN_MAX_MEMORY   2097152                            // 2 MiB (fast)

// CryptoNight variant 1 ("cnv1") tweaks. GhostRider always uses variant 1, so
// these are unconditional here (the reference guards them with `variant == 1`).
#define VARIANT1_1( p ) \
  do { \
    const uint8_t tmp = ((const uint8_t*)(p))[11]; \
    static const uint32_t table = 0x75310; \
    const uint8_t index = (((tmp >> 3) & 6) | (tmp & 1)) << 1; \
    ((uint8_t*)(p))[11] = tmp ^ ((table >> index) & 0x30); \
  } while(0)

#define VARIANT1_2( p ) \
  do { ((uint64_t*)(p))[1] ^= tweak1_2; } while(0)

#pragma pack(push, 1)
union cn_slow_hash_state
{
   union hash_state hs;
   struct
   {
      uint8_t k[64];
      uint8_t init[INIT_SIZE_BYTE];
   };
};
#pragma pack(pop)

extern void aesb_single_round( const uint8_t *in, uint8_t *out, uint8_t *expandedKey );
extern void aesb_pseudo_round( const uint8_t *in, uint8_t *out, uint8_t *expandedKey );

static void do_blake_hash ( const void *input, size_t len, char *output )
{ blake256_hash( (uint8_t*)output, input, len ); }

static void do_groestl_hash( const void *input, size_t len, char *output )
{ groestl( input, len * 8, (uint8_t*)output ); }

static void do_jh_hash( const void *input, size_t len, char *output )
{ int r = jh_hash( HASH_SIZE * 8, input, 8 * len, (uint8_t*)output );
  assert( SUCCESS == r ); (void)r; }

static void do_skein_hash( const void *input, size_t len, char *output )
{ int r = c_skein_hash( 8 * HASH_SIZE, input, 8 * len, (uint8_t*)output );
  assert( SKEIN_SUCCESS == r ); (void)r; }

static void ( * const extra_hashes[4] )( const void *, size_t, char * ) =
   { do_blake_hash, do_groestl_hash, do_jh_hash, do_skein_hash };

static inline void copy_block( uint8_t *dst, const uint8_t *src )
{
   ((uint64_t*)dst)[0] = ((uint64_t*)src)[0];
   ((uint64_t*)dst)[1] = ((uint64_t*)src)[1];
}

static inline void xor_blocks( uint8_t *a, const uint8_t *b )
{
   ((uint64_t*)a)[0] ^= ((uint64_t*)b)[0];
   ((uint64_t*)a)[1] ^= ((uint64_t*)b)[1];
}

static inline void xor_blocks_dst( const uint8_t *a, const uint8_t *b, uint8_t *dst )
{
   ((uint64_t*)dst)[0] = ((uint64_t*)a)[0] ^ ((uint64_t*)b)[0];
   ((uint64_t*)dst)[1] = ((uint64_t*)a)[1] ^ ((uint64_t*)b)[1];
}

// Scratchpad allocation backing. CryptoNight's random scratchpad walk is
// latency-bound; 2 MiB huge pages cut TLB misses substantially. Try explicit
// hugetlb (needs a reserved pool, e.g. vm.nr_hugepages), then transparent huge
// pages (no pool needed), then fall back to plain malloc.
enum { CN_BACK_MALLOC = 0, CN_BACK_THP = 1, CN_BACK_HUGETLB = 2 };
#define CN_HP_2M  ( (size_t)2 * 1024 * 1024 )

static volatile int cn_backing_seen = -1;   // first observed backing, for reporting

static void *cn_alloc( size_t size, int *kind )
{
   void *p = malloc_hugepages( size );      // explicit MAP_HUGETLB (>= 6 MiB)
   if ( p ) *kind = CN_BACK_HUGETLB;
   else
   {
      *kind = CN_BACK_MALLOC;
      p = NULL;
#if defined(__linux__) && defined(MADV_HUGEPAGE)
      const size_t rounded = ( size + CN_HP_2M - 1 ) & ~( CN_HP_2M - 1 );
      void *m = mmap( NULL, rounded, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
      if ( m != MAP_FAILED )
      {
         madvise( m, rounded, MADV_HUGEPAGE );
         p = m;
         *kind = CN_BACK_THP;
      }
#endif
      if ( !p ) { p = malloc( size ); *kind = CN_BACK_MALLOC; }
   }
   if ( cn_backing_seen < 0 ) cn_backing_seen = *kind;
   return p;
}

static void cn_free( void *p, size_t size, int kind )
{
   if ( !p ) return;
#if defined(__linux__)
   if ( kind != CN_BACK_MALLOC )
   {
      munmap( p, ( size + CN_HP_2M - 1 ) & ~( CN_HP_2M - 1 ) );
      return;
   }
#endif
   free( p );
}

const char *cryptonight_scratchpad_backing( void )
{
   switch ( cn_backing_seen )
   {
      case CN_BACK_HUGETLB: return "2M huge pages (hugetlb)";
      case CN_BACK_THP:     return "2M huge pages (transparent)";
      case CN_BACK_MALLOC:  return "malloc (4K pages)";
      default:              return "unallocated";
   }
}

// Per-thread scratchpads, lazily allocated to the largest variant (2 MiB).
// One for the single-hash path; a contiguous GR_CN_LANES-wide block for the
// interleaved multi-way path (each lane strided by CN_MAX_MEMORY).
static __thread uint8_t *cn_long_state = NULL;
static __thread uint8_t *cn_long_state_nway = NULL;
static __thread int cn_kind = CN_BACK_MALLOC;
static __thread int cn_kind_nway = CN_BACK_MALLOC;

static uint8_t *get_scratchpad( void )
{
   if ( cn_long_state == NULL )
      cn_long_state = (uint8_t*)cn_alloc( CN_MAX_MEMORY, &cn_kind );
   return cn_long_state;
}

static uint8_t *get_scratchpad_nway( void )
{
   if ( cn_long_state_nway == NULL )
      cn_long_state_nway =
         (uint8_t*)cn_alloc( (size_t)GR_CN_LANES * CN_MAX_MEMORY, &cn_kind_nway );
   return cn_long_state_nway;
}

void cryptonight_free_scratchpad( void )
{
   if ( cn_long_state )
   { cn_free( cn_long_state, CN_MAX_MEMORY, cn_kind ); cn_long_state = NULL; }
   if ( cn_long_state_nway )
   { cn_free( cn_long_state_nway, (size_t)GR_CN_LANES * CN_MAX_MEMORY,
              cn_kind_nway ); cn_long_state_nway = NULL; }
}

#if !defined(__AES__)

// CryptoNight v1, parameterized by total scratchpad memory (init fill), the
// number of main-loop iterations, and the byte addressing mask (16-aligned).
// Portable table soft-AES reference.
static void cryptonight_v1_hash_soft( const void *input, void *output, uint32_t len,
                                 uint32_t memory, uint32_t iters, uint32_t mask )
{
   union cn_slow_hash_state state;
   uint8_t *long_state = get_scratchpad();
   uint8_t text[INIT_SIZE_BYTE];
   uint8_t a[AES_BLOCK_SIZE];
   uint8_t b[AES_BLOCK_SIZE];
   uint8_t c[AES_BLOCK_SIZE];
   uint8_t aes_key[AES_KEY_SIZE];
   oaes_ctx *aes_ctx;
   size_t i, j;

   hash_process( &state.hs, (const uint8_t*)input, len );
   memcpy( text, state.init, INIT_SIZE_BYTE );
   memcpy( aes_key, state.hs.b, AES_KEY_SIZE );
   aes_ctx = (oaes_ctx*)oaes_alloc();

   // cnv1 tweak seed (requires len >= 43; GhostRider feeds 64-byte buffers).
   const uint64_t tweak1_2 =
      *(const uint64_t*)( ((const uint8_t*)input) + 35 ) ^ state.hs.w[24];

   // Expand the scratchpad.
   oaes_key_import_data( aes_ctx, aes_key, AES_KEY_SIZE );
   for ( i = 0; i < memory / INIT_SIZE_BYTE; i++ )
   {
      for ( j = 0; j < INIT_SIZE_BLK; j++ )
         aesb_pseudo_round( &text[ AES_BLOCK_SIZE * j ],
                            &text[ AES_BLOCK_SIZE * j ],
                            aes_ctx->key->exp_data );
      memcpy( &long_state[ i * INIT_SIZE_BYTE ], text, INIT_SIZE_BYTE );
   }

   for ( i = 0; i < AES_BLOCK_SIZE; i++ )
   {
      a[i] = state.k[i]      ^ state.k[32 + i];
      b[i] = state.k[16 + i] ^ state.k[48 + i];
   }

   // Main memory-hard loop.
   for ( i = 0; i < iters; i++ )
   {
      // Iteration 1: address from a, AES-round, store c^b.
      j = ( *(uint64_t*)a ) & mask;
      aesb_single_round( &long_state[j], c, a );
      xor_blocks_dst( c, b, &long_state[j] );
      VARIANT1_1( &long_state[j] );

      // Iteration 2: address from c, 128-bit multiply-accumulate.
      j = ( *(uint64_t*)c ) & mask;
      uint64_t *dst = (uint64_t*)&long_state[j];
      uint64_t t0 = dst[0], t1 = dst[1];
      uint64_t hi, lo = mul128( ((uint64_t*)c)[0], t0, &hi );

      ((uint64_t*)a)[0] += hi;
      ((uint64_t*)a)[1] += lo;
      dst[0] = ((uint64_t*)a)[0];
      dst[1] = ((uint64_t*)a)[1];
      ((uint64_t*)a)[0] ^= t0;
      ((uint64_t*)a)[1] ^= t1;
      VARIANT1_2( &long_state[j] );

      copy_block( b, c );
   }

   // Collapse the scratchpad back into the state.
   memcpy( text, state.init, INIT_SIZE_BYTE );
   oaes_key_import_data( aes_ctx, &state.hs.b[32], AES_KEY_SIZE );
   for ( i = 0; i < memory / INIT_SIZE_BYTE; i++ )
   {
      for ( j = 0; j < INIT_SIZE_BLK; j++ )
      {
         xor_blocks( &text[ j * AES_BLOCK_SIZE ],
                     &long_state[ i * INIT_SIZE_BYTE + j * AES_BLOCK_SIZE ] );
         aesb_pseudo_round( &text[ j * AES_BLOCK_SIZE ],
                            &text[ j * AES_BLOCK_SIZE ],
                            aes_ctx->key->exp_data );
      }
   }
   memcpy( state.init, text, INIT_SIZE_BYTE );

   hash_permutation( &state.hs );
   extra_hashes[ state.hs.b[0] & 3 ]( &state, 200, output );
   oaes_free( (OAES_CTX**)&aes_ctx );
}

#define cn_v1_hash cryptonight_v1_hash_soft

#else  // __AES__ : hardware AES-NI back end

// sl_xor(a1 a2 a3 a4) = a1 (a2^a1) (a3^a2^a1) (a4^a3^a2^a1)
static inline __m128i cn_sl_xor( __m128i t1 )
{
   __m128i t4 = _mm_slli_si128( t1, 4 );
   t1 = _mm_xor_si128( t1, t4 );
   t4 = _mm_slli_si128( t4, 4 );
   t1 = _mm_xor_si128( t1, t4 );
   t4 = _mm_slli_si128( t4, 4 );
   return _mm_xor_si128( t1, t4 );
}

// AES-256 key schedule producing the 10 round keys CryptoNight uses, matching
// the soft-AES (oaes) expansion. rcon must be a compile-time constant.
#define CN_GENKEY_STEP( rcon ) do { \
   __m128i x1 = _mm_aeskeygenassist_si128( x2, (rcon) ); \
   x1 = _mm_shuffle_epi32( x1, 0xFF ); \
   x0 = cn_sl_xor( x0 ); x0 = _mm_xor_si128( x0, x1 ); \
   x1 = _mm_aeskeygenassist_si128( x0, 0x00 ); \
   x1 = _mm_shuffle_epi32( x1, 0xAA ); \
   x2 = cn_sl_xor( x2 ); x2 = _mm_xor_si128( x2, x1 ); \
} while ( 0 )

static inline void cn_aes_genkey( const void *key32, __m128i k[10] )
{
   __m128i x0 = _mm_loadu_si128( (const __m128i*)key32 );
   __m128i x2 = _mm_loadu_si128( (const __m128i*)key32 + 1 );
   k[0] = x0; k[1] = x2;
   CN_GENKEY_STEP( 0x01 ); k[2] = x0; k[3] = x2;
   CN_GENKEY_STEP( 0x02 ); k[4] = x0; k[5] = x2;
   CN_GENKEY_STEP( 0x04 ); k[6] = x0; k[7] = x2;
   CN_GENKEY_STEP( 0x08 ); k[8] = x0; k[9] = x2;
}

// 10-round AES pseudo-round (scratchpad explode/implode).
static inline __m128i cn_aes10( __m128i b, const __m128i k[10] )
{
   b = _mm_aesenc_si128( b, k[0] );  b = _mm_aesenc_si128( b, k[1] );
   b = _mm_aesenc_si128( b, k[2] );  b = _mm_aesenc_si128( b, k[3] );
   b = _mm_aesenc_si128( b, k[4] );  b = _mm_aesenc_si128( b, k[5] );
   b = _mm_aesenc_si128( b, k[6] );  b = _mm_aesenc_si128( b, k[7] );
   b = _mm_aesenc_si128( b, k[8] );  b = _mm_aesenc_si128( b, k[9] );
   return b;
}

// CryptoNight v1, AES-NI. Same algorithm and parameters as the soft path.
static void cryptonight_v1_hash_aes( const void *input, void *output, uint32_t len,
                                     uint32_t memory, uint32_t iters, uint32_t mask )
{
   union cn_slow_hash_state state;
   uint8_t *long_state = get_scratchpad();
   __m128i text[INIT_SIZE_BLK];
   __m128i k[10];
   size_t i, j;

   hash_process( &state.hs, (const uint8_t*)input, len );

   const uint64_t tweak1_2 =
      *(const uint64_t*)( ((const uint8_t*)input) + 35 ) ^ state.hs.w[24];

   // Explode the scratchpad (init key = state[0..32]).
   cn_aes_genkey( state.hs.b, k );
   memcpy( text, state.init, INIT_SIZE_BYTE );
   for ( i = 0; i < memory / INIT_SIZE_BYTE; i++ )
   {
      for ( j = 0; j < INIT_SIZE_BLK; j++ )
         text[j] = cn_aes10( text[j], k );
      memcpy( &long_state[ i * INIT_SIZE_BYTE ], text, INIT_SIZE_BYTE );
   }

   uint64_t a0 = ((uint64_t*)state.k)[0] ^ ((uint64_t*)state.k)[4];
   uint64_t a1 = ((uint64_t*)state.k)[1] ^ ((uint64_t*)state.k)[5];
   __m128i bx = _mm_xor_si128( _mm_loadu_si128( (const __m128i*)(state.k + 16) ),
                               _mm_loadu_si128( (const __m128i*)(state.k + 48) ) );
   __m128i ax = _mm_set_epi64x( (long long)a1, (long long)a0 );
   j = a0 & mask;

   // Main memory-hard loop.
   for ( i = 0; i < iters; i++ )
   {
      // Iteration 1: AES round, store c^b.
      __m128i *p0 = (__m128i*)&long_state[j];
      __m128i cx = _mm_aesenc_si128( _mm_load_si128( p0 ), ax );
      _mm_store_si128( p0, _mm_xor_si128( bx, cx ) );
      VARIANT1_1( (uint8_t*)p0 );

      // Iteration 2: 128-bit multiply-accumulate.
      uint64_t cl = (uint64_t)_mm_cvtsi128_si64( cx );
      uint64_t *q = (uint64_t*)&long_state[ cl & mask ];
      uint64_t t0 = q[0], t1 = q[1];
      uint64_t hi, lo = mul128( cl, t0, &hi );
      a0 += hi; a1 += lo;
      q[0] = a0;
      q[1] = a1 ^ tweak1_2;            // store, then VARIANT1_2 on the high word
      a0 ^= t0; a1 ^= t1;

      ax = _mm_set_epi64x( (long long)a1, (long long)a0 );
      bx = cx;
      j = a0 & mask;
   }

   // Implode the scratchpad (collapse key = state[32..64]).
   cn_aes_genkey( state.hs.b + 32, k );
   memcpy( text, state.init, INIT_SIZE_BYTE );
   for ( i = 0; i < memory / INIT_SIZE_BYTE; i++ )
      for ( j = 0; j < INIT_SIZE_BLK; j++ )
      {
         text[j] = _mm_xor_si128( text[j],
            _mm_load_si128( (const __m128i*)&long_state[ i * INIT_SIZE_BYTE
                                                       + j * AES_BLOCK_SIZE ] ) );
         text[j] = cn_aes10( text[j], k );
      }
   memcpy( state.init, text, INIT_SIZE_BYTE );

   hash_permutation( &state.hs );
   extra_hashes[ state.hs.b[0] & 3 ]( &state, 200, output );
}

// Interleaved GR_CN_LANES-way CryptoNight v1 (AES-NI). Each lane is an
// independent CN hash with its own scratchpad; the main loop is split into
// AES / store / post phases issued across all lanes so one lane's scratchpad
// load latency overlaps another lane's compute. Software prefetch of each
// lane's next (data-dependent) address further hides latency.
static void cryptonight_v1_Nway_aes( const void *const in[GR_CN_LANES],
                                     void *const out[GR_CN_LANES], uint32_t len,
                                     uint32_t memory, uint32_t iters, uint32_t mask )
{
   union cn_slow_hash_state state[GR_CN_LANES];
   uint8_t *base = get_scratchpad_nway();
   uint8_t *ls[GR_CN_LANES];
   __m128i  text[INIT_SIZE_BLK], k[10];
   uint64_t a0[GR_CN_LANES], a1[GR_CN_LANES], tweak[GR_CN_LANES], cl[GR_CN_LANES];
   __m128i  bx[GR_CN_LANES], cx[GR_CN_LANES];
   size_t   j[GR_CN_LANES], a1addr[GR_CN_LANES];
   int l;
   size_t i, b;

   for ( l = 0; l < GR_CN_LANES; l++ )
   {
      ls[l] = base + (size_t)l * CN_MAX_MEMORY;

      hash_process( &state[l].hs, (const uint8_t*)in[l], len );
      tweak[l] = *(const uint64_t*)( ((const uint8_t*)in[l]) + 35 )
                 ^ state[l].hs.w[24];

      // Explode lane l.
      cn_aes_genkey( state[l].hs.b, k );
      memcpy( text, state[l].init, INIT_SIZE_BYTE );
      for ( i = 0; i < memory / INIT_SIZE_BYTE; i++ )
      {
         for ( b = 0; b < INIT_SIZE_BLK; b++ )
            text[b] = cn_aes10( text[b], k );
         memcpy( &ls[l][ i * INIT_SIZE_BYTE ], text, INIT_SIZE_BYTE );
      }

      a0[l] = ((uint64_t*)state[l].k)[0] ^ ((uint64_t*)state[l].k)[4];
      a1[l] = ((uint64_t*)state[l].k)[1] ^ ((uint64_t*)state[l].k)[5];
      bx[l] = _mm_xor_si128(
                 _mm_loadu_si128( (const __m128i*)(state[l].k + 16) ),
                 _mm_loadu_si128( (const __m128i*)(state[l].k + 48) ) );
      j[l]  = a0[l] & mask;
   }

   for ( i = 0; i < iters; i++ )
   {
      // AES phase: cx = aes(ls[j], a); compute & prefetch the iter-2 address.
      for ( l = 0; l < GR_CN_LANES; l++ )
      {
         __m128i ax = _mm_set_epi64x( (long long)a1[l], (long long)a0[l] );
         cx[l] = _mm_aesenc_si128( _mm_load_si128( (__m128i*)&ls[l][ j[l] ] ), ax );
         cl[l] = (uint64_t)_mm_cvtsi128_si64( cx[l] );
         a1addr[l] = cl[l] & mask;
         _mm_prefetch( (const char*)&ls[l][ a1addr[l] ], _MM_HINT_T0 );
      }
      // Store phase: ls[j] = b ^ cx; cnv1 tweak; advance b.
      for ( l = 0; l < GR_CN_LANES; l++ )
      {
         __m128i *p0 = (__m128i*)&ls[l][ j[l] ];
         _mm_store_si128( p0, _mm_xor_si128( bx[l], cx[l] ) );
         VARIANT1_1( (uint8_t*)p0 );
         bx[l] = cx[l];
      }
      // Post phase: 128-bit multiply-accumulate; compute & prefetch next addr.
      for ( l = 0; l < GR_CN_LANES; l++ )
      {
         uint64_t *q = (uint64_t*)&ls[l][ a1addr[l] ];
         uint64_t t0 = q[0], t1 = q[1], hi, lo = mul128( cl[l], t0, &hi );
         a0[l] += hi; a1[l] += lo;
         q[0] = a0[l];
         q[1] = a1[l] ^ tweak[l];
         a0[l] ^= t0; a1[l] ^= t1;
         j[l] = a0[l] & mask;
         _mm_prefetch( (const char*)&ls[l][ j[l] ], _MM_HINT_T0 );
      }
   }

   for ( l = 0; l < GR_CN_LANES; l++ )
   {
      // Implode lane l.
      cn_aes_genkey( state[l].hs.b + 32, k );
      memcpy( text, state[l].init, INIT_SIZE_BYTE );
      for ( i = 0; i < memory / INIT_SIZE_BYTE; i++ )
         for ( b = 0; b < INIT_SIZE_BLK; b++ )
         {
            text[b] = _mm_xor_si128( text[b],
               _mm_load_si128( (const __m128i*)&ls[l][ i * INIT_SIZE_BYTE
                                                     + b * AES_BLOCK_SIZE ] ) );
            text[b] = cn_aes10( text[b], k );
         }
      memcpy( state[l].init, text, INIT_SIZE_BYTE );

      hash_permutation( &state[l].hs );
      extra_hashes[ state[l].hs.b[0] & 3 ]( &state[l], 200, out[l] );
   }
}

#define cn_v1_hash cryptonight_v1_hash_aes

#endif // __AES__

// MEM       iters    mask
// turtle/turtlelite : 256 KiB  2^16
// dark/darklite     : 512 KiB  2^17
// lite              :   1 MiB  2^18
// fast              :   2 MiB  2^18
// "lite" variants address only the lower half of the scratchpad.

void cryptonightturtlelite_hash( const void *in, void *out, uint32_t len, int variant )
{ (void)variant; cn_v1_hash( in, out, len, 262144, 65536, 131056 ); }

void cryptonightturtle_hash( const void *in, void *out, uint32_t len, int variant )
{ (void)variant; cn_v1_hash( in, out, len, 262144, 65536, 262128 ); }

void cryptonightdarklite_hash( const void *in, void *out, uint32_t len, int variant )
{ (void)variant; cn_v1_hash( in, out, len, 524288, 131072, 262128 ); }

void cryptonightdark_hash( const void *in, void *out, uint32_t len, int variant )
{ (void)variant; cn_v1_hash( in, out, len, 524288, 131072, 524272 ); }

void cryptonightlite_hash( const void *in, void *out, uint32_t len, int variant )
{ (void)variant; cn_v1_hash( in, out, len, 1048576, 262144, 1048560 ); }

void cryptonightfast_hash( const void *in, void *out, uint32_t len, int variant )
{ (void)variant; cn_v1_hash( in, out, len, 2097152, 262144, 2097136 ); }

// (memory, iterations, mask) per CNAlgo index {dark, darklite, fast, lite,
// turtle, turtlelite} = 0..5 — matches gr-gate.c's enum CNAlgo order.
static const struct { uint32_t memory, iters, mask; } cn_params[6] =
{
   { 524288,  131072, 524272  },   // CNDark
   { 524288,  131072, 262128  },   // CNDarklite
   { 2097152, 262144, 2097136 },   // CNFast
   { 1048576, 262144, 1048560 },   // CNLite
   { 262144,  65536,  262128  },   // CNTurtle
   { 262144,  65536,  131056  },   // CNTurtlelite
};

void cryptonight_4way( int cn_variant, const void *in[GR_CN_LANES],
                       void *out[GR_CN_LANES], uint32_t len )
{
   const uint32_t mem = cn_params[cn_variant].memory;
   const uint32_t it  = cn_params[cn_variant].iters;
   const uint32_t mk  = cn_params[cn_variant].mask;
#if defined(__AES__)
   cryptonight_v1_Nway_aes( in, out, len, mem, it, mk );
#else
   for ( int l = 0; l < GR_CN_LANES; l++ )
      cn_v1_hash( in[l], out[l], len, mem, it, mk );
#endif
}
