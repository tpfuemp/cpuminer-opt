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
