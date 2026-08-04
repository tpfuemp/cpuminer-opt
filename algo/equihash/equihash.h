#ifndef EQUIHASH_H
#define EQUIHASH_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ── Algorithm parameters ────────────────────────────────────────────── */

typedef struct {
    int     wn;               /* hash bit-length (n)                         */
    int     wk;               /* tree depth (k)                              */
    int     collision_bits;   /* wn / (wk+1)                                 */
    int     cbl;              /* CollisionByteLength = ceil(collision_bits/8) */
    int     hash_length;      /* HashLength = (wk+1)*cbl  (expanded format)  */
    int     proofsize;        /* 2^wk  (indices per solution)                */
    int     nhashes_init;     /* 2^(collision_bits+1)  (initial list)        */
    int     max_rows;         /* row capacity: nhashes_init + EH_ROW_SLACK%  */
    int     hashlen;          /* ceil(wn/8) raw bytes per Blake2b hash value */
    int     slot_bytes;       /* hash_length + 4 (hash + min_idx LE32)       */
    int     nbuckets;         /* min(1<<collision_bits, 1<<20)               */
    int     index_bits;       /* collision_bits + 1                          */
    int     solution_size;    /* ceil(proofsize * index_bits / 8)            */
    uint8_t personalization[16]; /* "PersonStr" || LE32(wn) || LE32(wk)     */
} eh_params_t;

/* Row capacity slack, in percent of nhashes_init.
 *
 * A Wagner round turns n rows into ~n^2/nhashes_init rows, so nhashes_init is a
 * fixed point of the row count — but an UNSTABLE one. Sizing the buffers at
 * exactly nhashes_init makes wagner_round's cap equal the mean: upward
 * fluctuations are truncated while downward ones compound into every later
 * round, so the population ratchets down and solutions are lost with it.
 * Measured on 200/9 over 160 nonces: at 0% slack 18% of rounds hit the cap and
 * the final row count decays to 1.92M of 2.10M, yielding 1.71 solutions per
 * solve; at 10% it is 7%, 2.06M and 1.86 solutions (+9.2%) for 2% more row
 * work. The gain is flat from there (1.85 at 15%, 1.87 at 25%), so 10% buys
 * essentially all of it at the smallest memory cost.                        */
#define EH_ROW_SLACK_PCT 10

/* Workspace size estimates (slot_bytes = hash_length + 4, N = max_rows):
 *
 *   Variant  slot  hbuf×2          pairs(wk×N×8)    sort   buckets  Total
 *   96/5      16B  2×0.14M×16=5MB  5×0.14M×8=6MB   0.6MB   0.5MB  ~11 MB
 *   200/9     34B  2×2.3M×34=150MB 9×2.3M×8=158MB   9MB     8MB   ~325 MB
 *   144/5     22B  2×37M×22=1.5GB  5×37M×8=1.5GB  148MB  128MB   ~3.3 GB
 *   192/7     28B  2×37M×28=2.0GB  7×37M×8=2.0GB  148MB  128MB   ~4.2 GB
 *   125/4     24B  2×74M×24=3.5GB  4×74M×8=2.4GB  295MB  264MB   ~6.4 GB
 *
 * eh_workspace_alloc() sizes dynamically via eh_workspace_bytes().         */

/* Predefined variants — initialized on first use, not thread-safe to modify */
extern eh_params_t EH_PARAMS_200_9;    /* ZCash, Horizen, Komodo (200/9)    */
extern eh_params_t EH_PARAMS_144_5;    /* Bitcoin Gold (144/5)              */
extern eh_params_t EH_PARAMS_192_7;    /* ZeroClassic (192/7)               */
extern eh_params_t EH_PARAMS_96_5;     /* MinexCoin etc. (96/5)             */
extern eh_params_t EH_PARAMS_125_4;    /* Flux / ZelCash (125/4)            */

/* Build params from pool-sent strings (params[8] and params[9] of notify).
 * wn_wk_str: e.g. "200_9" or "144_5"
 * personal8:  e.g. "ZcashPoW" — exactly 8 printable chars (pool-sent)
 * Returns false on parse error (invalid format).                          */
bool eh_params_from_stratum(eh_params_t *out, const char *wn_wk_str,
                             const char *personal8);

/* ── Dynamic workspace ───────────────────────────────────────────────── */

/* Single flat allocation parcelled into named regions. */
typedef struct {
    uint8_t  *hbuf0;          /* max_rows × slot_bytes                   */
    uint8_t  *hbuf1;          /* max_rows × slot_bytes                   */
    uint32_t *pairs;          /* wk × max_rows × 2 (flat)                */
    uint32_t *sort_orig;      /* max_rows entries                        */
    uint32_t *bucket_start;   /* nbuckets + 1 entries                    */
    uint32_t *bucket_size;    /* nbuckets entries                        */
    uint32_t  round_cnt[12];  /* k+1 entries (k ≤ 10)                   */
    eh_params_t params;       /* copy of parameters used to build this   */
    void     *_base;          /* raw buffer pointer (for free)           */
    size_t    _size;          /* allocated bytes (rounded for huge pages)*/
    int       _mem_kind;      /* allocator used (eh_mem_kind_t) for free */
} eh_workspace_t;

/* How _base was allocated, so eh_workspace_free uses the matching deallocator
 * (munmap / VirtualFree must NOT be free()d). See item 3 in the optimization
 * plan (huge-page workspace).                                                 */
typedef enum {
    EH_MEM_MALLOC = 0,   /* plain malloc()                / free()          */
    EH_MEM_MMAP   = 1,   /* Linux mmap (HUGETLB or THP)   / munmap()        */
    EH_MEM_VALLOC = 2,   /* Windows VirtualAlloc large pg / VirtualFree()   */
} eh_mem_kind_t;

/* Compute required workspace bytes for given parameters. */
size_t eh_workspace_bytes(const eh_params_t *p);

/* Allocate (or reallocate) a workspace.
 * Pass existing *ws to resize in-place (frees old allocation first).
 * Returns false on OOM; *ws is untouched on failure.                      */
bool eh_workspace_alloc(eh_workspace_t **ws, const eh_params_t *p);

/* Free a workspace. */
void eh_workspace_free(eh_workspace_t *ws);

/* ── Solver ──────────────────────────────────────────────────────────── */

/* Run the Wagner solver for one (header, nonce) pair.
 * header must be EQH_WORK_DATA_SIZE (140) bytes; nonce is at bytes 108-139.
 * solutions: caller array, each EH_MAX_SOLUTION_BYTES bytes.
 * Returns number of solutions written (0–max_sols).                       */
#define EH_MAX_SOLUTION_BYTES 1344   /* maximum across all supported variants */
/* Solutions per solve are ~Poisson(1.9) for 200/9, so a cap of 4 truncated the
 * solve loop on ~4% of solves and cost 3.5% of all solutions. 16 makes the
 * truncation unreachable in practice for 21 KB of caller stack.            */
#define EH_MAX_SOLS           16

/* Difficulty scale factor between the pool-reported difficulty and the
 * cpuminer-opt internal diff scale (hash_to_diff / diff_to_hash):
 *
 *   diff_pool     = diff_to_target_equi uses 0xFFFF0000 as the numerator
 *   diff_internal = hash_to_diff uses 2^32 as the numerator
 *
 *   diff_pool = diff_internal × EQH_DIFF_SCALE
 *   EQH_DIFF_SCALE = 0xFFFF0000 >> 8 = 0x00FFFF00 = 16776960
 *
 * Used in two places:
 *   util.c/stratum_set_target:     next_diff = diff_internal × EQH_DIFF_SCALE
 *   equihash-gate.c/register_*:   opt_target_factor = EQH_DIFF_SCALE
 *
 * The opt_target_factor makes stratum_gen_work compute:
 *   g_work->targetdiff = diff_pool / EQH_DIFF_SCALE = diff_internal
 * so diff_to_hash reconstructs the correct pool target.                   */
#define EQH_DIFF_SCALE  16776960.0   /* 0x00FFFF00 = 0xFFFF0000 >> 8 */

int equihash_solve(const uint8_t *header, eh_workspace_t *ws,
                   uint8_t solutions[][EH_MAX_SOLUTION_BYTES], int max_sols);

/* Verify a packed solution against a header.  Returns true if valid. */
bool equihash_verify(const uint8_t *header, const eh_params_t *p,
                     const uint8_t *solution, size_t sol_len);

/* ── Solver backend (reference vs optimized split) ───────────────────────── */

/* The three hot kernels are dispatched through this vtable so an optimized
 * (SIMD/NEON) backend can replace them without touching the arch-neutral
 * orchestration, workspace, reconstruction, packing or verifier in equihash.c.
 *
 *   gen_hashes   : fill hbuf0 with Blake2b+ExpandArray hashes for all indices
 *   bucket_sort  : counting-sort hbuf0[0..n_src) into hbuf1 by collision group,
 *                  populating sort_orig[] and bucket_start[]/bucket_size[]
 *   wagner_round : merge colliding pairs from hbuf1 into hbuf0, record pairs[],
 *                  return the number of output rows (<= max_out)              */
typedef struct {
    const char *name;
    void     (*gen_hashes)  (const uint8_t *header, eh_workspace_t *ws);
    void     (*bucket_sort) (uint32_t n_src, eh_workspace_t *ws);
    uint32_t (*wagner_round)(int round, uint32_t n_in, uint32_t max_out,
                             eh_workspace_t *ws);
} eh_backend_t;

/* Reference kernels, exposed so optimized backends can reuse the ones they
 * have not specialized yet (equihash-ref.c). */
void     eh_ref_gen_hashes  (const uint8_t *header, eh_workspace_t *ws);
void     eh_ref_bucket_sort (uint32_t n_src, eh_workspace_t *ws);
uint32_t eh_ref_wagner_round(int round, uint32_t n_in, uint32_t max_out,
                             eh_workspace_t *ws);

/* Scalar reference backend — always compiled; correctness oracle (equihash-ref.c). */
extern const eh_backend_t eh_backend_ref;

/* Optimized backend — Blake2b midstate hash-gen now; SIMD later
 * (equihash-simd.c). Reuses the reference bucket_sort/wagner_round until those
 * are specialized. Must produce byte-identical output to the reference.       */
extern const eh_backend_t eh_backend_simd;

/* Differential oracle: run the reference and optimized backends on the same
 * input and confirm identical output. Returns true if they agree (or if only
 * the reference exists). Used to gate backend selection.                      */
bool eh_backend_selftest(void);

/* Active backend. Returns the optimized backend iff it passed the differential
 * self-test, otherwise the reference. Result is cached after first call;
 * trigger it once single-threaded (at registration) before miner threads run. */
const eh_backend_t *eh_active_backend(void);

#endif /* EQUIHASH_H */
