#ifndef BALLOON_H__
#define BALLOON_H__ 1

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Balloon (Boneh-Corrigan-Gibbs-Schechter 2016) as Mateable (MTBC) uses it.
 *
 *   salt     = header bytes 0..31
 *   buf[0]   = SHA256( LE64(ctr++) || salt || header[0..79]
 *                      || LE64(s_cost) || LE32(t_cost) )
 *   buf[i]   = SHA256( LE64(ctr++) || buf[i-1] )                i = 1..n-1
 *   t_cost times, for i = 0..n-1:
 *       buf[i] = SHA256( LE64(ctr++) || buf[i ? i-1 : n-1] || buf[i]
 *                        || buf[idx++] || buf[idx++] || buf[idx++] )
 *   digest   = buf[n-1]
 *
 * The counter is hashed as 8 raw little-endian bytes.                        */

#define BALLOON_S_COST        128            /* KiB                          */
#define BALLOON_T_COST          4            /* mixing rounds                */
#define BALLOON_BLOCK_SIZE     32            /* bytes per block (SHA-256)    */
#define BALLOON_SALT_LEN       32            /* = header bytes 0..31         */
#define BALLOON_N_NEIGHBORS     3            /* random blocks mixed in       */
#define BALLOON_INPUT_LEN      80            /* the whole block header       */

/* n_blocks = s_cost * 1024 / block_size, rounded up to even (it already is). */
#define BALLOON_N_BLOCKS   ( ( BALLOON_S_COST * 1024 ) / BALLOON_BLOCK_SIZE )

/* One index per neighbour per block per round, consumed as one running
 * sequence across all rounds.                                               */
#define BALLOON_N_INDICES  ( (size_t)BALLOON_T_COST * BALLOON_N_BLOCKS \
                             * BALLOON_N_NEIGHBORS )

/* Indices are stored as uint16_t, which holds any n_blocks up to 65536. */
typedef char balloon_index_fits_u16[ BALLOON_N_BLOCKS <= 65536 ? 1 : -1 ];

/* ── Index bitstream ──────────────────────────────────────────────────────
 *
 * The index stream depends only on the salt, i.e. on header bytes 0-31, so it
 * is nonce-independent: build it once per block, not once per hash.
 *
 *   key    = SHA256( salt[32] || LE64(s_cost) || LE32(t_cost) )   (44 B in)
 *   stream = AES-128-CTR( key[0..15], IV = 0 ) over zeros
 *   idx[j] = LE64( stream[8j .. 8j+7] ) mod n_blocks
 *
 * Only the first 16 bytes of the 32-byte digest key the cipher — that is what
 * OpenSSL's EVP_aes_128_ctr does with the same 32-byte buffer upstream.      */

/* Derive the 32-byte bitstream seed digest. */
void balloon_bitstream_key( uint8_t key[32], const uint8_t salt[BALLOON_SALT_LEN],
                            int64_t s_cost, int32_t t_cost );

/* Fill `idx` with BALLOON_N_INDICES reduced block indices for this salt. */
void balloon_build_indices( uint16_t *idx,
                            const uint8_t salt[BALLOON_SALT_LEN] );

/* Raw keystream, exposed for testing. */
void balloon_bitstream_raw( uint8_t *out, size_t outlen,
                            const uint8_t salt[BALLOON_SALT_LEN],
                            int64_t s_cost, int32_t t_cost );

/* ── Scratch ──────────────────────────────────────────────────────────────
 *
 * 224 KiB: the 128 KiB working buffer plus a 96 KiB index table. Both are
 * fixed size, so this is one object with no allocation inside the hash.
 *
 * The index table is cached across calls and rebuilt whenever the salt
 * changes. That test is part of the construction, not an optimization:
 * reusing another header's indices produces a well-formed digest for the
 * wrong index sequence, which a pool rejects with nothing to debug.
 *
 * One context per thread. It is mutable state, so two threads sharing one is
 * the "works at -t 1, garbage at -t 16" bug.                               */

typedef struct
{
   uint8_t  buf[ BALLOON_N_BLOCKS * BALLOON_BLOCK_SIZE ];
   uint16_t idx[ BALLOON_N_INDICES ];
   uint8_t  idx_salt[ BALLOON_SALT_LEN ];    /* which salt `idx` is for */
   bool     idx_valid;
} balloon_ctx __attribute__((aligned(64)));

/* Mark the cached index table unusable. Only needed to force a rebuild; the
 * salt comparison already covers correctness.                               */
static inline void balloon_ctx_reset( balloon_ctx *ctx )
{
   ctx->idx_valid = false;
}

/* The sanctioned way to get one: per-thread, 64-byte aligned, allocated on
 * first use and never freed — miner threads outlive it. Returns NULL if the
 * allocation failed, which the caller must treat as "cannot hash" rather than
 * carry on with.                                                            */
balloon_ctx *balloon_thread_ctx( void );

/* 80-byte header in, 32-byte digest out. Named for the input rather than just
 * `balloon_hash`, which other implementations export with a different
 * signature — a test that links both would otherwise not compile.           */
void balloon_hash_header( balloon_ctx *ctx, const void *input, void *digest );

/* Run every known-answer vector. NULL if they all pass, otherwise the name of
 * the first that failed. A failure is fatal — see balloon-kat.h.            */
const char *balloon_self_test( void );

#endif /* BALLOON_H__ */
