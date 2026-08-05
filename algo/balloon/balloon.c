/* Balloon (Mateable) — the AES-128-CTR block-index stream and its SHA-256 key
 * derivation, plus the hash construction itself. The stream depends only on
 * the salt, so it is built once per block and reused across every nonce hashed
 * against it.                                                               */

#include "balloon.h"
#include "balloon-aes128.h"
#include "balloon-kat.h"
#include "algo/sha/sha256-hash.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <malloc.h>
#define posix_memalign(p, a, s) (((*(p)) = _aligned_malloc((s), (a))), *(p) ?0 :errno)
#endif

/* Every integer the construction hashes is little-endian, written out byte by
 * byte so no digest depends on host endianness.                              */

static inline void balloon_put_le64( uint8_t *p, uint64_t v )
{
   for ( int i = 0; i < 8; i++ ) p[i] = (uint8_t)( v >> ( 8*i ) );
}

static inline void balloon_put_le32( uint8_t *p, uint32_t v )
{
   for ( int i = 0; i < 4; i++ ) p[i] = (uint8_t)( v >> ( 8*i ) );
}

void balloon_bitstream_key( uint8_t key[32], const uint8_t salt[BALLOON_SALT_LEN],
                            int64_t s_cost, int32_t t_cost )
{
   uint8_t seed[ BALLOON_SALT_LEN + 8 + 4 ];

   memcpy( seed, salt, BALLOON_SALT_LEN );
   balloon_put_le64( seed + BALLOON_SALT_LEN,     (uint64_t)s_cost );
   balloon_put_le32( seed + BALLOON_SALT_LEN + 8, (uint32_t)t_cost );

   sha256_full( key, seed, sizeof seed );
}

void balloon_bitstream_raw( uint8_t *out, size_t outlen,
                            const uint8_t salt[BALLOON_SALT_LEN],
                            int64_t s_cost, int32_t t_cost )
{
   uint8_t key[32];
   balloon_aes128_ctx aes;

   balloon_bitstream_key( key, salt, s_cost, t_cost );
   balloon_aes128_init( &aes, key );          /* first 16 bytes of the digest */
   balloon_aes128_keystream( &aes, 0, out, outlen );
}

void balloon_build_indices( uint16_t *idx, const uint8_t salt[BALLOON_SALT_LEN] )
{
   uint8_t key[32];
   balloon_aes128_ctx aes;
   uint8_t block[16];

   balloon_bitstream_key( key, salt, BALLOON_S_COST, BALLOON_T_COST );
   balloon_aes128_init( &aes, key );

   /* Two indices per 16-byte keystream block, generated in place rather than
    * materialising the whole ~384 KB byte stream first.                     */
   uint64_t counter = 0;
   for ( size_t j = 0; j < BALLOON_N_INDICES; j += 2 )
   {
      balloon_aes128_keystream( &aes, counter++, block, 16 );

      for ( int half = 0; half < 2; half++ )
      {
         if ( j + half >= BALLOON_N_INDICES ) break;

         const uint8_t *b = block + 8*half;
         uint64_t v = 0;
         for ( int i = 7; i >= 0; i-- ) v = ( v << 8 ) | b[i];   /* LE64 */

         idx[ j + half ] = (uint16_t)( v % BALLOON_N_BLOCKS );
      }
   }
}

/* ── The hash ─────────────────────────────────────────────────────────────
 *
 * Three phases, all of them SHA-256 over a small contiguous buffer: fill
 * block 0 from the header, expand it into a chain across the whole buffer,
 * then t_cost mixing rounds that rewrite every block in place from its
 * predecessor, itself, and BALLOON_N_NEIGHBORS indexed blocks.
 *
 * `counter` is hashed as the first 8 bytes of every one of those digests and
 * runs unbroken across all three phases: 1 + (n-1) + t_cost*n compressions.
 * The index sequence likewise runs unbroken across the mixing rounds.       */

#define BALLOON_MIX_BLOCKS  ( 2 + BALLOON_N_NEIGHBORS )
#define BALLOON_LAST        ( ( BALLOON_N_BLOCKS - 1 ) * BALLOON_BLOCK_SIZE )

void balloon_hash_header( balloon_ctx *ctx, const void *input, void *digest )
{
   const uint8_t *in  = (const uint8_t*)input;
   const uint8_t *salt = in;                 /* header bytes 0..31 */
   uint8_t *buf = ctx->buf;
   uint64_t counter = 0;

   /* The index stream is a function of the salt alone, so it survives a nonce
    * change and is rebuilt only when the salt moves — see balloon.h.        */
   if ( !ctx->idx_valid
        || memcmp( ctx->idx_salt, salt, BALLOON_SALT_LEN ) != 0 )
   {
      balloon_build_indices( ctx->idx, salt );
      memcpy( ctx->idx_salt, salt, BALLOON_SALT_LEN );
      ctx->idx_valid = true;
   }

   /* Fill: the salt appears twice, once on its own and once as the head of
    * the full header. That is the construction, not a transcription slip.   */
   {
      uint8_t seed[ 8 + BALLOON_SALT_LEN + BALLOON_INPUT_LEN + 8 + 4 ];
      uint8_t *p = seed;

      balloon_put_le64( p, counter++ );                p += 8;
      memcpy( p, salt, BALLOON_SALT_LEN );             p += BALLOON_SALT_LEN;
      memcpy( p, in, BALLOON_INPUT_LEN );              p += BALLOON_INPUT_LEN;
      balloon_put_le64( p, BALLOON_S_COST );           p += 8;
      balloon_put_le32( p, BALLOON_T_COST );

      sha256_full( buf, seed, sizeof seed );
   }

   /* Expand: buf[i] = SHA256( LE64(ctr++) || buf[i-1] ). */
   {
      uint8_t msg[ 8 + BALLOON_BLOCK_SIZE ];

      for ( int i = 1; i < BALLOON_N_BLOCKS; i++ )
      {
         balloon_put_le64( msg, counter++ );
         memcpy( msg + 8, buf + ( i - 1 ) * BALLOON_BLOCK_SIZE,
                 BALLOON_BLOCK_SIZE );
         sha256_full( buf + i * BALLOON_BLOCK_SIZE, msg, sizeof msg );
      }
   }

   /* Mix. Blocks are updated in place, so a neighbour already visited this
    * round contributes its new value and one not yet visited its old one —
    * that sequential dependency is what makes the hash memory-hard.         */
   {
      uint8_t msg[ 8 + BALLOON_BLOCK_SIZE * BALLOON_MIX_BLOCKS ];
      const uint16_t *idx = ctx->idx;

      for ( int round = 0; round < BALLOON_T_COST; round++ )
      for ( int i = 0; i < BALLOON_N_BLOCKS; i++ )
      {
         uint8_t *cur = buf + i * BALLOON_BLOCK_SIZE;

         balloon_put_le64( msg, counter++ );
         memcpy( msg + 8, i ? cur - BALLOON_BLOCK_SIZE : buf + BALLOON_LAST,
                 BALLOON_BLOCK_SIZE );
         memcpy( msg + 8 + BALLOON_BLOCK_SIZE, cur, BALLOON_BLOCK_SIZE );

         for ( int k = 0; k < BALLOON_N_NEIGHBORS; k++ )
            memcpy( msg + 8 + BALLOON_BLOCK_SIZE * ( 2 + k ),
                    buf + *idx++ * BALLOON_BLOCK_SIZE, BALLOON_BLOCK_SIZE );

         sha256_full( cur, msg, sizeof msg );
      }
   }

   memcpy( digest, buf + BALLOON_LAST, BALLOON_BLOCK_SIZE );
}

/* ── Per-thread scratch ───────────────────────────────────────────────────
 *
 * GPU miners keep the equivalents — the index buffer and the block scratch —
 * at file scope, which is fine for one host thread per device and a data race
 * here, where -t N threads run this code. It is not a benign race either: the
 * index table feeds the digest, so two threads on different jobs would quietly
 * mine rejects rather than crash.                                           */

static __thread balloon_ctx *tl_ctx = NULL;

balloon_ctx *balloon_thread_ctx( void )
{
   if ( !tl_ctx )
   {
      void *p = NULL;
      if ( posix_memalign( &p, 64, sizeof( balloon_ctx ) ) || !p )
         return NULL;
      tl_ctx = (balloon_ctx*)p;
      balloon_ctx_reset( tl_ctx );
   }
   return tl_ctx;
}

/* ── Self-test ────────────────────────────────────────────────────────────
 *
 * Checked from the innermost primitive outwards so a failure localises: the
 * cipher, then the index bitstream built on it, then the whole construction.
 * See balloon-kat.h for where each vector comes from.                       */

const char *balloon_self_test( void )
{
   balloon_aes128_ctx aes;
   uint8_t out[64];

   balloon_aes128_init( &aes, balloon_kat_aes_key );
   balloon_aes128_encrypt_block( &aes, balloon_kat_aes_in, out );
   if ( memcmp( out, balloon_kat_aes_out, 16 ) )
      return "AES-128, FIPS-197 C.1";

   balloon_bitstream_key( out, balloon_kat_salt,
                          BALLOON_S_COST, BALLOON_T_COST );
   if ( memcmp( out, balloon_kat_key, 32 ) )
      return "index bitstream key derivation";

   balloon_bitstream_raw( out, 64, balloon_kat_salt,
                          BALLOON_S_COST, BALLOON_T_COST );
   if ( memcmp( out, balloon_kat_keystream, 64 ) )
      return "index bitstream keystream";

   /* Through the per-thread accessor, so startup also proves the 224 KiB
    * allocation works rather than leaving it to the first hash.             */
   balloon_ctx *ctx = balloon_thread_ctx();
   if ( !ctx ) return "scratch allocation";

   for ( size_t i = 0; i < BALLOON_N_KATS; i++ )
   {
      balloon_hash_header( ctx, balloon_kats[i].header, out );
      if ( memcmp( out, balloon_kats[i].digest, BALLOON_BLOCK_SIZE ) )
         return balloon_kats[i].name;
   }

   return NULL;
}
