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
    int     pairs_per_round;  /* nhashes_init (one full round of pairs)      */
    int     hashlen;          /* ceil(wn/8) raw bytes per Blake2b hash value */
    int     slot_bytes;       /* hash_length + 4 (hash + min_idx LE32)       */
    int     nbuckets;         /* min(1<<collision_bits, 1<<20)               */
    int     index_bits;       /* collision_bits + 1                          */
    int     solution_size;    /* ceil(proofsize * index_bits / 8)            */
    uint8_t personalization[16]; /* "PersonStr" || LE32(wn) || LE32(wk)     */
} eh_params_t;

/* Workspace size estimates (slot_bytes = hash_length + 4, pairs = nhashes_init):
 *
 *   Variant  slot  hbuf×2          pairs(wk×N×8)    sort   buckets  Total
 *   96/5      16B  2×0.13M×16=4MB  5×0.13M×8=5MB   0.5MB   0.5MB  ~10 MB
 *   200/9     34B  2×2M×34=136MB   9×2M×8=144MB    8MB     8MB    ~296 MB
 *   144/5     22B  2×33M×22=1.4GB  5×33M×8=1.3GB  134MB  128MB   ~3.0 GB
 *   192/7     28B  2×33M×28=1.8GB  7×33M×8=1.8GB  134MB  128MB   ~3.8 GB
 *   125/4     24B  2×67M×24=3.2GB  4×67M×8=2.1GB  268MB  264MB   ~5.8 GB
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
    uint8_t  *hbuf0;          /* nhashes_init × slot_bytes               */
    uint8_t  *hbuf1;          /* nhashes_init × slot_bytes               */
    uint32_t *pairs;          /* wk × pairs_per_round × 2 (flat)         */
    uint32_t *sort_orig;      /* nhashes_init entries                    */
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
#define EH_MAX_SOLS            4

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
 * See docs/EQUIHASH_OPTIMIZATION_PLAN.md, item 0.
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
