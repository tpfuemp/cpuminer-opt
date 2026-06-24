// Copyright (c) 2012-2013 The Cryptonote developers
// Portions Copyright (c) 2018 The Monero developers
// Portions Copyright (c) 2018 The TurtleCoin Developers
// Distributed under the MIT/X11 software license.
//
// GhostRider CryptoNight (variant 1) core, parameterized for the six GR
// variants. Scalar / portable reference implementation: table-based soft AES
// (aesb.c) and keccak-based init/finalize (crypto/hash.c). See cryptonight.h
// for the per-variant parameter table.

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cryptonight.h"
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

// Per-thread scratchpad, lazily allocated to the largest variant (2 MiB).
static __thread uint8_t *cn_long_state = NULL;

static uint8_t *get_scratchpad( void )
{
   if ( cn_long_state == NULL )
      cn_long_state = (uint8_t*)malloc( CN_MAX_MEMORY );
   return cn_long_state;
}

void cryptonight_free_scratchpad( void )
{
   if ( cn_long_state ) { free( cn_long_state ); cn_long_state = NULL; }
}

// CryptoNight v1, parameterized by total scratchpad memory (init fill), the
// number of main-loop iterations, and the byte addressing mask (16-aligned).
static void cryptonight_v1_hash( const void *input, void *output, uint32_t len,
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

// MEM       iters    mask
// turtle/turtlelite : 256 KiB  2^16
// dark/darklite     : 512 KiB  2^17
// lite              :   1 MiB  2^18
// fast              :   2 MiB  2^18
// "lite" variants address only the lower half of the scratchpad.

void cryptonightturtlelite_hash( const void *in, void *out, uint32_t len, int variant )
{ (void)variant; cryptonight_v1_hash( in, out, len, 262144, 65536, 131056 ); }

void cryptonightturtle_hash( const void *in, void *out, uint32_t len, int variant )
{ (void)variant; cryptonight_v1_hash( in, out, len, 262144, 65536, 262128 ); }

void cryptonightdarklite_hash( const void *in, void *out, uint32_t len, int variant )
{ (void)variant; cryptonight_v1_hash( in, out, len, 524288, 131072, 262128 ); }

void cryptonightdark_hash( const void *in, void *out, uint32_t len, int variant )
{ (void)variant; cryptonight_v1_hash( in, out, len, 524288, 131072, 524272 ); }

void cryptonightlite_hash( const void *in, void *out, uint32_t len, int variant )
{ (void)variant; cryptonight_v1_hash( in, out, len, 1048576, 262144, 1048560 ); }

void cryptonightfast_hash( const void *in, void *out, uint32_t len, int variant )
{ (void)variant; cryptonight_v1_hash( in, out, len, 2097152, 262144, 2097136 ); }
