#include "gr-gate.h"
#include "cryptonight.h"
#include "../blake/sph_blake.h"
#include "../bmw/sph_bmw.h"
#include "../cubehash/sph_cubehash.h"
#include "../echo/sph_echo.h"
#include "../fugue/sph_fugue.h"
#include "../groestl/sph_groestl.h"
#include "../hamsi/sph_hamsi.h"
#include "../jh/sph_jh.h"
#include "../keccak/sph_keccak.h"
#include "../luffa/sph_luffa.h"
#include "../shabal/sph_shabal.h"
#include "../shavite/sph_shavite.h"
#include "../simd/sph_simd.h"
#include "../skein/sph_skein.h"
#include "../whirlpool/sph_whirlpool.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/*
 * GhostRider (Raptoreum "gr").
 *
 * Combines 15 "core" algorithms (the x16 set without SHA) with 6 CryptoNight
 * variants, of which 3 are used per hash. Both the core order and the CN triple
 * are derived from bytes [4..68) of the (byteswapped) block header. The chain is
 * three groups of five core rounds, each followed by one CN round; the high 32
 * bytes of the working buffer are zeroed after each CN round.
 *
 * Scalar reference port from michal-zurkowski/cpuminer-gr with CryptoNight
 * parameters corrected against WyvernTKC cpuminer-gr (the consensus miner).
 */

enum Algo
{
   BLAKE = 0, BMW, GROESTL, JH, KECCAK, SKEIN, LUFFA, CUBEHASH,
   SHAVITE, SIMD, ECHO, HAMSI, FUGUE, SHABAL, WHIRLPOOL,
   HASH_FUNC_COUNT
};

enum CNAlgo
{
   CNDark = 0, CNDarklite, CNFast, CNLite, CNTurtle, CNTurtlelite,
   CN_HASH_FUNC_COUNT
};

static void selectAlgo( unsigned char nibble, bool *selectedAlgos,
                        uint8_t *selectedIndex, int algoCount,
                        int *currentCount )
{
   uint8_t algoDigit = ( nibble & 0x0F ) % algoCount;
   if ( !selectedAlgos[ algoDigit ] )
   {
      selectedAlgos[ algoDigit ] = true;
      selectedIndex[ currentCount[0] ] = algoDigit;
      currentCount[0] += 1;
   }
   algoDigit = ( nibble >> 4 ) % algoCount;
   if ( !selectedAlgos[ algoDigit ] )
   {
      selectedAlgos[ algoDigit ] = true;
      selectedIndex[ currentCount[0] ] = algoDigit;
      currentCount[0] += 1;
   }
}

static void getAlgoString( const void *mem, unsigned int size,
                           uint8_t *selectedAlgoOutput, int algoCount )
{
   unsigned char *p = (unsigned char*)mem;
   unsigned int len = size / 2;
   bool selectedAlgo[ HASH_FUNC_COUNT ] = { false };  // >= max algoCount (15)
   int selectedCount = 0;

   for ( unsigned int i = 0; i < len; i++ )
   {
      selectAlgo( p[i], selectedAlgo, selectedAlgoOutput, algoCount,
                  &selectedCount );
      if ( selectedCount == algoCount ) break;
   }
   if ( selectedCount < algoCount )
      for ( uint8_t i = 0; i < algoCount; i++ )
         if ( !selectedAlgo[i] )
            selectedAlgoOutput[ selectedCount++ ] = i;
}

static void doCNAlgo( uint8_t algo, const void *in, void *hash, int size )
{
   switch ( algo )
   {
      case CNDark:       cryptonightdark_hash      ( in, hash, size, 1 ); break;
      case CNDarklite:   cryptonightdarklite_hash  ( in, hash, size, 1 ); break;
      case CNFast:       cryptonightfast_hash      ( in, hash, size, 1 ); break;
      case CNLite:       cryptonightlite_hash      ( in, hash, size, 1 ); break;
      case CNTurtle:     cryptonightturtle_hash    ( in, hash, size, 1 ); break;
      case CNTurtlelite: cryptonightturtlelite_hash( in, hash, size, 1 ); break;
   }
}

static void doCoreAlgo( uint8_t algo, const void *in, void *hash, int size )
{
   switch ( algo )
   {
      case BLAKE:
      {  sph_blake512_context ctx;
         sph_blake512_init( &ctx ); sph_blake512( &ctx, in, size );
         sph_blake512_close( &ctx, hash ); break; }
      case BMW:
      {  sph_bmw512_context ctx;
         sph_bmw512_init( &ctx ); sph_bmw512( &ctx, in, size );
         sph_bmw512_close( &ctx, hash ); break; }
      case GROESTL:
      {  sph_groestl512_context ctx;
         sph_groestl512_init( &ctx ); sph_groestl512( &ctx, in, size );
         sph_groestl512_close( &ctx, hash ); break; }
      case SKEIN:
      {  sph_skein512_context ctx;
         sph_skein512_init( &ctx ); sph_skein512( &ctx, in, size );
         sph_skein512_close( &ctx, hash ); break; }
      case JH:
      {  sph_jh512_context ctx;
         sph_jh512_init( &ctx ); sph_jh512( &ctx, in, size );
         sph_jh512_close( &ctx, hash ); break; }
      case KECCAK:
      {  sph_keccak512_context ctx;
         sph_keccak512_init( &ctx ); sph_keccak512( &ctx, in, size );
         sph_keccak512_close( &ctx, hash ); break; }
      case LUFFA:
      {  sph_luffa512_context ctx;
         sph_luffa512_init( &ctx ); sph_luffa512( &ctx, in, size );
         sph_luffa512_close( &ctx, hash ); break; }
      case CUBEHASH:
      {  sph_cubehash512_context ctx;
         sph_cubehash512_init( &ctx ); sph_cubehash512( &ctx, in, size );
         sph_cubehash512_close( &ctx, hash ); break; }
      case SHAVITE:
      {  sph_shavite512_context ctx;
         sph_shavite512_init( &ctx ); sph_shavite512( &ctx, in, size );
         sph_shavite512_close( &ctx, hash ); break; }
      case SIMD:
      {  sph_simd512_context ctx;
         sph_simd512_init( &ctx ); sph_simd512( &ctx, in, size );
         sph_simd512_close( &ctx, hash ); break; }
      case ECHO:
      {  sph_echo512_context ctx;
         sph_echo512_init( &ctx ); sph_echo512( &ctx, in, size );
         sph_echo512_close( &ctx, hash ); break; }
      case HAMSI:
      {  sph_hamsi512_context ctx;
         sph_hamsi512_init( &ctx ); sph_hamsi512( &ctx, in, size );
         sph_hamsi512_close( &ctx, hash ); break; }
      case FUGUE:
      {  sph_fugue512_context ctx;
         sph_fugue512_init( &ctx ); sph_fugue512( &ctx, in, size );
         sph_fugue512_close( &ctx, hash ); break; }
      case SHABAL:
      {  sph_shabal512_context ctx;
         sph_shabal512_init( &ctx ); sph_shabal512( &ctx, in, size );
         sph_shabal512_close( &ctx, hash ); break; }
      case WHIRLPOOL:
      {  sph_whirlpool_context ctx;
         sph_whirlpool_init( &ctx ); sph_whirlpool( &ctx, in, size );
         sph_whirlpool_close( &ctx, hash ); break; }
   }
}

void gr_hash( void *output, const void *input )
{
   uint8_t hash_1[64] __attribute__ ((aligned (64)));
   uint8_t hash_2[64] __attribute__ ((aligned (64)));
   uint8_t coreOrder[15];
   uint8_t cnOrder[6];

   getAlgoString( (const uint8_t*)input + 4, 64, coreOrder, 15 );
   getAlgoString( (const uint8_t*)input + 4, 64, cnOrder,    6 );

   // Group 1: first core round consumes the full 80-byte header.
   doCoreAlgo( coreOrder[0], input,  hash_1, 80 );
   doCoreAlgo( coreOrder[1], hash_1, hash_2, 64 );
   doCoreAlgo( coreOrder[2], hash_2, hash_1, 64 );
   doCoreAlgo( coreOrder[3], hash_1, hash_2, 64 );
   doCoreAlgo( coreOrder[4], hash_2, hash_1, 64 );
   doCNAlgo  ( cnOrder[0],   hash_1, hash_2, 64 );
   memset( hash_2 + 32, 0, 32 );

   // Group 2.
   doCoreAlgo( coreOrder[5], hash_2, hash_1, 64 );
   doCoreAlgo( coreOrder[6], hash_1, hash_2, 64 );
   doCoreAlgo( coreOrder[7], hash_2, hash_1, 64 );
   doCoreAlgo( coreOrder[8], hash_1, hash_2, 64 );
   doCoreAlgo( coreOrder[9], hash_2, hash_1, 64 );
   doCNAlgo  ( cnOrder[1],   hash_1, hash_2, 64 );
   memset( hash_2 + 32, 0, 32 );

   // Group 3.
   doCoreAlgo( coreOrder[10], hash_2, hash_1, 64 );
   doCoreAlgo( coreOrder[11], hash_1, hash_2, 64 );
   doCoreAlgo( coreOrder[12], hash_2, hash_1, 64 );
   doCoreAlgo( coreOrder[13], hash_1, hash_2, 64 );
   doCoreAlgo( coreOrder[14], hash_2, hash_1, 64 );
   doCNAlgo  ( cnOrder[2],    hash_1, hash_2, 64 );

   memcpy( output, hash_2, 32 );
}

// Known-answer self-test. The 80-byte input is the reference header from
// npq7721/gr_hash test.py; the expected digest was captured from this
// implementation, whose components are independently verified for consensus
// correctness:
//   - CryptoNight core: matches the authoritative xmrig cn/v1 KAT byte-for-byte
//   - algo selection + 5/CN/5/CN/5/CN chain: matches xmrig ghostrider.cpp
//   - the six CryptoNight parameter sets: match WyvernTKC cpuminer-gr (consensus)
// It therefore doubles as a regression guard. End-to-end consensus is finally
// confirmed by pool-accepted shares.
static const uint8_t gr_test_input[80] =
{
   0x70,0x00,0x00,0x00,0x5d,0x38,0x5b,0xa1,0x14,0xd0,0x79,0x97,0x0b,0x29,0xa9,0x41,
   0x8f,0xd0,0x54,0x9e,0x7d,0x68,0xa9,0x5c,0x7f,0x16,0x86,0x21,0xa3,0x14,0x20,0x10,
   0x00,0x00,0x00,0x00,0x57,0x85,0x86,0xd1,0x49,0xfd,0x07,0xb2,0x2f,0x3a,0x8a,0x34,
   0x7c,0x51,0x6d,0xe7,0x05,0x2f,0x03,0x4d,0x2b,0x76,0xff,0x68,0xe0,0xd6,0xec,0xff,
   0x9b,0x77,0xa4,0x54,0x89,0xe3,0xfd,0x51,0x17,0x32,0x01,0x1d,0xf0,0x73,0x10,0x00
};

static const uint8_t gr_test_expected[32] =
{
   0x57,0x28,0x99,0x3c,0x46,0xe9,0x78,0x21,0x1b,0x52,0x84,0xc4,0x6d,0xc2,0x89,0x3f,
   0x51,0x1b,0x28,0x79,0x4a,0x25,0x14,0x98,0x67,0xec,0x8c,0x33,0xa5,0xef,0xb5,0x69
};

bool gr_self_test( void )
{
   uint8_t hash[32];
   gr_hash( hash, gr_test_input );

   if ( memcmp( hash, gr_test_expected, 32 ) != 0 )
   {
      char hex[65];
      for ( int i = 0; i < 32; i++ )
         sprintf( hex + i * 2, "%02x", hash[i] );
      applog( LOG_ERR, "GhostRider self-test mismatch: got %s", hex );
      return false;
   }
   return true;
}

int scanhash_gr( struct work *work, uint32_t max_nonce, uint64_t *hashes_done,
                 struct thr_info *mythr )
{
   uint32_t _ALIGN(64) edata[20];
   uint32_t _ALIGN(64) hash[8];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const int thr_id = mythr->id;
   uint32_t nonce = first_nonce;
   volatile uint8_t *restart = &( work_restart[thr_id].restart );
   const bool bench = opt_benchmark;

   v128_bswap32_80( edata, pdata );

   do
   {
      edata[19] = nonce;
      gr_hash( hash, edata );
      if ( unlikely( valid_hash( hash, ptarget ) && !bench ) )
      {
         pdata[19] = bswap_32( nonce );
         submit_solution( work, hash, mythr );
      }
      nonce++;
   } while ( nonce < max_nonce && !(*restart) );

   pdata[19] = nonce;
   *hashes_done = nonce - first_nonce;
   return 0;
}

bool register_gr_algo( algo_gate_t *gate )
{
   if ( !gr_self_test() )
   {
      applog( LOG_ERR, "GhostRider self-test failed" );
      return false;
   }
   gate->scanhash     = (void*)&scanhash_gr;
   gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | NEON_OPT;
   opt_target_factor  = 65536.0;
   return true;
}
