#ifndef RANDOMX_GATE_H
#define RANDOMX_GATE_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "algo-gate-api.h"

/* The nonce sits at byte offset 39 of the Monero hashing blob, 4 bytes little
 * endian. Confirmed against xmrig Job::nonceOffset() (39 for the RandomX
 * family) and against live jobs from the pool. */
#define RX_NONCE_OFFSET 39
#define RX_BLOB_MAX     128

/* The shared miner loop tracks the nonce as work->data[algo_gate.nonce_index]
 * and relies on being able to increment it (std_get_new_work's `else
 * ++(*nonceptr)` is what stops a found share being re-found and submitted as a
 * duplicate). Byte offset 39 is not 4-byte aligned, so no word index can alias
 * the real nonce. Instead the nonce lives in a scratch word PAST the blob:
 * scanhash copies it into the blob at offset 39 before each hash. Word 32 is
 * the first word beyond a maximum-size (128-byte) blob, and work->data has 48.
 */
#define RX_NONCE_WORD   32

struct randomx_vm;

/* --- randomx-vm.c : cache/dataset/VM lifecycle -------------------------- */

/* Rebuild cache+dataset for `seed` if it differs from the current one.
 * Blocking; must be called with no miner thread inside scanhash (see the
 * deadlock note in randomx-vm.c). */
bool rx_seed_update( const unsigned char *seed );

bool rx_vm_pool_init( int nthreads );
void rx_vm_free( int thr_id );
struct randomx_vm *rx_vm_get( int thr_id );   /* caller holds the read lock */
void rx_read_lock( void );
/* True while a dataset rebuild is wanted or running. scanhash MUST check this
 * and return without taking the read lock -- see randomx-vm.c, this is what
 * stops the readers starving the rebuild's writer. */
bool rx_reseed_is_pending( void );
void rx_read_unlock( void );
uint64_t rx_current_epoch( void );

/* Test hook: forget the current seed so the next job forces a real rebuild.
 * Driven by CPUMINER_RX_TEST_RESEED=<seconds>; see randomx-vm.c. */
void rx_force_reseed_for_test( void );
bool rx_is_full_mode( void );

/* --- randomx-variant.c : which RandomX variant this run mines ----------- */

/* Only salt-only variants belong here; anything touching a VM or JIT constant
 * needs its own compiled core. See randomx-variant.c. */
typedef struct
{
   int                  algo;       /* ALGO_RANDOMX, ALGO_RANDOMX_SFX, ... */
   const char          *pool_algo;  /* the pool's "algo" string, e.g. "rx/sfx" */
   const unsigned char *salt;       /* NULL = the core's compile-time default */
   unsigned int         salt_len;
   /* Startup check for this variant. A real published or accepted-share
    * vector where one exists; NULL falls back to the generic
    * rx_kat_variant_differs() differential, which is all that is possible
    * before a variant has ever been accepted by a pool. */
   bool               (*selftest)( void );
   /* Which compiled core hashes this variant. Tier-1 variants share the stock
    * core and differ only by the runtime salt above; tier-2 variants need
    * their own, because they move constants the core bakes into constexprs
    * and into an immediate in hand-written assembly. NULL = stock. */
   const struct rx_core_s *core;
} rx_variant_t;

/* Set membership, so the several `opt_algo == ALGO_RANDOMX` tests in the
 * shared code do not have to grow a term per variant -- each one gates
 * protocol dialect or connection behaviour, and missing one silently speaks
 * the wrong dialect. */
bool rx_algo_is_randomx( int algo );

const rx_variant_t *rx_variant( void );
const char *rx_variant_pool_algo( void );

/* Applies the variant's salt to the core. Must be called before the first
 * cache init and never again. */
bool rx_variant_select( int algo );

/* --- randomx-stratum.c : the Monero stratum dialect --------------------- */

/* Replaces subscribe+authorize. Sends "login", parses the session id and the
 * job embedded in the result. */
bool rx_stratum_login( struct stratum_ctx *sctx, const char *user,
                       const char *pass );

/* Handles a {"method":"job"} push. Returns false if it was not one. */
bool rx_stratum_job( struct stratum_ctx *sctx, json_t *params );

/* Called from stratum_thread before stratum_gen_work: brings the dataset in
 * line with the pending job's seed_hash. */
bool rx_stratum_prepare_seed( struct stratum_ctx *sctx );

/* Copies the pending job into g_work. Replaces the coinbase/merkle path. */
void rx_stratum_gen_work( struct stratum_ctx *sctx, struct work *g_work );

/* Monero "submit" instead of "mining.submit". */
void rx_build_stratum_request( char *req, struct work *work,
                               struct stratum_ctx *sctx );

/* Monero replies {"result":{"status":"OK"}} / {"error":{"message":...}} rather
 * than a bare boolean and an array, so the shared response path cannot read
 * them. Returns false if this message is not a submit reply. *reason points
 * into `val`; the caller owns and must decref it. */
bool rx_stratum_parse_response( json_t *val, bool *accepted,
                                const char **reason );

/* --- randomx-gate.c ----------------------------------------------------- */

bool register_randomx_algo( algo_gate_t *gate );

/* --- randomx-kat.c ------------------------------------------------------ */

/* Quick startup self-test: argon2 cache fill + one interpreter and one JIT
 * vector. A subset of what `make check` runs; see randomx-kat.c for why. */
bool rx_kat_selftest( void );

/* Fallback check for a variant with no vector yet: the selected variant must
 * not hash identically to rx/0. Compares the two configurations against each
 * other, so it needs no vectors and covers both tiers. Lives in
 * randomx-variant.c because it must go through the SELECTED core -- the KAT
 * deliberately talks to the stock core only. */
bool rx_variant_differs_from_rx0( void );

/* rx/graft: three vectors reconstructed from shares a live Graft pool
 * accepted. Lives in randomx-variant.c, not the KAT, because a tier-2
 * variant must be hashed by its OWN core. */
bool rx_variant_graft_vectors( void );

/* rx/arq: two vectors from shares a live ArQmA pool accepted. */
bool rx_variant_arq_vectors( void );

/* rx/sfx: a real vector, reconstructed from a share a live Safex pool
 * accepted. Sets and restores the salt itself, so it is valid to call with
 * either the default or the variant salt in force. */
bool rx_kat_sfx_vector( void );
int  rx_kat_full( int full );

/* Measurement modes, driven by randomx-kat-main.c. cpuminer itself never calls
 * these -- `--benchmark` cannot work for randomx (no job means scanhash returns
 * early), so these exist because the alternative was measuring through a
 * vardiff pool at +-20% noise.
 *   rx_kat_bench: one-shot vs batched driver, single thread, ABBA in-process.
 *   rx_kat_sweep: thread-count sweep against one real dataset. */
int  rx_kat_bench( int nonces );
int  rx_kat_sweep( int nonces, int maxthreads );

#endif /* RANDOMX_GATE_H */
