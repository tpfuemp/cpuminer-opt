/*
 * HeavyHash proof-of-work - Optical Bitcoin (OBTC), Ursula (URSA).
 *
 *   seed       = SHA3-256( header80[4..35] )   // prev block hash, job-constant
 *   mat[64][64]= xoshiro256++(seed) -> 4-bit values, retried until full rank
 *   first      = SHA3-256( header80 )
 *   product[i] = ( sum_j mat[i][j] * nibbles(first)[j] ) >> 10
 *   digest     = SHA3-256( first ^ pack_nibbles(product) )
 *
 * Consensus-critical. The nibble order, the >> 10 reduction, the little-endian
 * uint64 seed decode and the full-rank retry all follow obtc-core: src/hash.cpp,
 * src/primitives/block.cpp, src/crypto/{heavyhash.cpp,xoshiro256pp.h}. URSA uses
 * the same algorithm.
 *
 * Two conventions that are easy to get wrong:
 *   - SHA3-256 padding, not Keccak: register_heavyhash_algo sets
 *     hard_coded_eb = 6 before any hashing, self-test included.
 *   - The digest is consumed as little-endian uint32 words, so there is no byte
 *     reversal before valid_hash.
 */

#include "heavyhash-gate.h"
#include "heavyhash-kat.h"
#include "../keccak/keccak-gate.h"      // hard_coded_eb
#include "../keccak/sph_keccak.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

static inline uint64_t heavyhash_le64dec( const void *pp )
{
   const uint8_t *p = (const uint8_t*)pp;
   return  (uint64_t)p[0]        | ( (uint64_t)p[1] <<  8 )
        | ( (uint64_t)p[2] << 16 ) | ( (uint64_t)p[3] << 24 )
        | ( (uint64_t)p[4] << 32 ) | ( (uint64_t)p[5] << 40 )
        | ( (uint64_t)p[6] << 48 ) | ( (uint64_t)p[7] << 56 );
}

static inline uint64_t heavyhash_rotl64( const uint64_t x, int k )
{
   return ( x << k ) | ( x >> ( 64 - k ) );
}

// xoshiro256++ -- the "++" scrambler, rotl(s0+s3,23)+s0. Not xoshiro256**,
// which some sources name it; the wrong scrambler changes every matrix element.
static inline uint64_t heavyhash_xoshiro_gen( struct heavyhash_xoshiro_state *st )
{
   const uint64_t result = heavyhash_rotl64( st->s[0] + st->s[3], 23 ) + st->s[0];
   const uint64_t t = st->s[1] << 17;

   st->s[2] ^= st->s[0];
   st->s[3] ^= st->s[1];
   st->s[1] ^= st->s[2];
   st->s[0] ^= st->s[3];
   st->s[2] ^= t;
   st->s[3] = heavyhash_rotl64( st->s[3], 45 );

   return result;
}

// Full-rank gate, computed exactly over a prime field. obtc-core uses a 64x64
// SVD (reject if the smallest singular value is < 1.000009e-12); full rank mod p
// implies nonsingular over the rationals, which implies that test passes. Two
// primes, because a nonsingular matrix can lose rank modulo one of them
// (chance ~1/p). Exact arithmetic keeps this file free of floating point.
//
// Entries are 4-bit, so a singular matrix is vanishingly unlikely and the retry
// loop runs once in practice. obtc-core's other gate, Is4BitPrecision, is
// omitted: `>> (4*shift) & 0xF` makes it true by construction.

#define HH_RANK_P1  2147483647u    /* 2^31-1, Mersenne prime */
#define HH_RANK_P2  2147483629u    /* prime */

static uint32_t hh_pow_mod( uint32_t base, uint32_t exp, uint32_t p )
{
   uint64_t result = 1, b = base;
   while ( exp )
   {
      if ( exp & 1 ) result = ( result * b ) % p;
      b = ( b * b ) % p;
      exp >>= 1;
   }
   return (uint32_t)result;
}

// Row-echelon reduction over GF(p); returns the number of pivots.
static int hh_rank_mod_p( const uint32_t A[64][64], uint32_t p )
{
   uint32_t a[64][64];
   memcpy( a, A, sizeof a );      // entries are 0..15, already reduced mod p

   int row = 0;
   for ( int col = 0; col < 64; ++col )
   {
      int piv = -1;
      for ( int r = row; r < 64; ++r )
         if ( a[r][col] ) { piv = r; break; }
      if ( piv < 0 ) continue;

      if ( piv != row )
         for ( int c = col; c < 64; ++c )
         {
            uint32_t t = a[row][c]; a[row][c] = a[piv][c]; a[piv][c] = t;
         }

      const uint32_t inv = hh_pow_mod( a[row][col], p - 2, p );
      for ( int c = col; c < 64; ++c )
         a[row][c] = (uint32_t)( ( (uint64_t)a[row][c] * inv ) % p );

      for ( int r = row + 1; r < 64; ++r )
         if ( a[r][col] )
         {
            const uint64_t f = a[r][col];
            for ( int c = col; c < 64; ++c )
               a[r][c] = (uint32_t)( ( a[r][c] + p
                                     - ( f * a[row][c] ) % p ) % p );
         }
      ++row;
   }
   return row;
}

static bool heavyhash_is_full_rank( const uint32_t matrix[64][64] )
{
   return hh_rank_mod_p( matrix, HH_RANK_P1 ) == 64
       || hh_rank_mod_p( matrix, HH_RANK_P2 ) == 64;
}

// Job-constant: reads header bytes 4..35 (the prev block hash) only, never
// nNonce at 76..79. The PRNG state is not reset between retries, so a rejected
// matrix advances the stream; that is consensus too.
void heavyhash_matrix_gen( const void *header80, uint32_t matrix[64][64] )
{
   struct heavyhash_xoshiro_state state;
   uint8_t seed[32];

   sph_keccak256_context ctx;
   sph_keccak256_init( &ctx );
   sph_keccak256( &ctx, (const uint8_t*)header80 + 4, 32 );
   sph_keccak256_close( &ctx, seed );

   for ( int i = 0; i < 4; ++i )
      state.s[i] = heavyhash_le64dec( seed + 8 * i );

   do {
      for ( int i = 0; i < 64; ++i )
         for ( int j = 0; j < 64; j += 16 )
         {
            uint64_t value = heavyhash_xoshiro_gen( &state );
            for ( int shift = 0; shift < 16; ++shift )
               matrix[i][j + shift] = ( value >> ( 4 * shift ) ) & 0xF;
         }
   } while ( !heavyhash_is_full_rank( matrix ) );
}

// Mining always passes len == 80; the length exists so obtc-core's own vectors
// (test/functional/heavy_hash.py, 1- and 4-byte inputs) can run verbatim.
void heavyhash_core_len( const uint32_t matrix[64][64], const void *data,
                         size_t len, void *output )
{
   uint8_t _ALIGN(64) hash_first[32];
   uint8_t _ALIGN(64) hash_xored[32];
   uint32_t vector[64];
   uint32_t product[64];
   sph_keccak256_context ctx;

   sph_keccak256_init( &ctx );
   sph_keccak256( &ctx, data, len );
   sph_keccak256_close( &ctx, hash_first );

   for ( int i = 0; i < 32; ++i )
   {
      vector[2*i    ] = hash_first[i] >> 4;
      vector[2*i + 1] = hash_first[i] & 0xF;
   }

   for ( int i = 0; i < 64; ++i )
   {
      uint32_t sum = 0;
      for ( int j = 0; j < 64; ++j )
         sum += matrix[i][j] * vector[j];
      product[i] = sum >> 10;
   }

   // Each product fits a nibble: max sum is 64*15*15 = 14400, >> 10 = 14.
   for ( int i = 0; i < 32; ++i )
      hash_xored[i] = hash_first[i]
                    ^ (uint8_t)( ( product[2*i] << 4 ) | product[2*i + 1] );

   sph_keccak256_init( &ctx );
   sph_keccak256( &ctx, hash_xored, 32 );
   sph_keccak256_close( &ctx, output );
}

void heavyhash_core( const uint32_t matrix[64][64], const void *header80,
                     void *output )
{
   heavyhash_core_len( matrix, header80, 80, output );
}

void heavyhash_hash( void *output, const void *input )
{
   uint32_t matrix[64][64];      // 16 KB
   heavyhash_matrix_gen( input, matrix );
   heavyhash_core( (const uint32_t (*)[64])matrix, input, output );
}

static void heavyhash_log_mismatch( const char *what, const uint8_t *got,
                                    const uint8_t *expected )
{
   char g[65], e[65];
   for ( int i = 0; i < 32; i++ )
   {
      sprintf( g + i*2, "%02x", got[i] );
      sprintf( e + i*2, "%02x", expected[i] );
   }
   applog( LOG_ERR, "heavyhash %s FAILED (consensus KAT mismatch)", what );
   applog( LOG_ERR, "  got:      %s", g );
   applog( LOG_ERR, "  expected: %s", e );
}

// Hard fail: a wrong digest means every share is rejected, so refusing to start
// is the cheap outcome. See heavyhash-kat.h for what the two groups cover.
bool heavyhash_self_test( void )
{
   uint8_t hash[32];

   for ( int v = 0; v < HEAVYHASH_KAT_HEADER_COUNT; v++ )
   {
      heavyhash_hash( hash, heavyhash_kat_header_input[v] );
      if ( memcmp( hash, heavyhash_kat_header_expected[v], 32 ) != 0 )
      {
         heavyhash_log_mismatch( heavyhash_kat_header_name[v], hash,
                                 heavyhash_kat_header_expected[v] );
         return false;
      }
   }

   for ( int v = 0; v < HEAVYHASH_KAT_CORE_COUNT; v++ )
   {
      heavyhash_core_len( heavyhash_kat_core_matrix,
                          heavyhash_kat_core_input[v],
                          heavyhash_kat_core_inlen[v], hash );
      if ( memcmp( hash, heavyhash_kat_core_expected[v], 32 ) != 0 )
      {
         heavyhash_log_mismatch( "obtc-core core vector", hash,
                                 heavyhash_kat_core_expected[v] );
         return false;
      }
   }

   applog( LOG_NOTICE, "heavyhash self-test PASSED (%d header + %d core "
           "consensus vectors, OBTC genesis anchored)",
           HEAVYHASH_KAT_HEADER_COUNT, HEAVYHASH_KAT_CORE_COUNT );
   return true;
}

int scanhash_heavyhash( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(64) hash32[8];
   uint32_t _ALIGN(64) edata[20];
   uint32_t _ALIGN(64) matrix[64][64];   // 16 KB, job-constant
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;
   uint32_t n = first_nonce;

   for ( int i = 0; i < 19; i++ )
      be32enc( &edata[i], pdata[i] );

   // Constant for this whole nonce range: build it once, not once per nonce.
   heavyhash_matrix_gen( edata, matrix );

   do {
      be32enc( &edata[19], n );
      heavyhash_core( (const uint32_t (*)[64])matrix, edata, hash32 );

      if ( unlikely( valid_hash( hash32, ptarget ) && !bench ) )
      {
         pdata[19] = n;
         submit_solution( work, hash32, mythr );
      }
      n++;
   } while ( likely( n < last_nonce && !work_restart[thr_id].restart ) );

   *hashes_done = n - first_nonce;
   pdata[19] = n;
   return 0;
}

bool register_heavyhash_algo( algo_gate_t *gate )
{
   // SHA3 padding, not Keccak. Must precede the self-test.
   hard_coded_eb = 6;

   if ( !heavyhash_self_test() )
   {
      applog( LOG_ERR, "heavyhash self-test failed" );
      return false;
   }
   gate->scanhash      = (void*)&scanhash_heavyhash;
   gate->hash          = (void*)&heavyhash_hash;
   gate->optimizations = SSE2_OPT | AVX2_OPT | NEON_OPT;
   // Plain 256-bit digest on a Bitcoin-style header: standard 0xffff difficulty
   // base. Confirmed against observed share difficulties.
   opt_target_factor   = 1.0;
   return true;
}
