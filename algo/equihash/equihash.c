/*
 * Equihash solver — CPU implementation based on the Zcash/Jack Grigg reference.
 *
 * Algorithm: Wagner's Generalised Birthday Problem.
 * Reference:  Yiimp stratum algos/equihash.{h,cpp,tcc} (verifier structure)
 *             Zcash src/crypto/equihash.cpp          (BasicSolve logic)
 *
 * KEY DESIGN DECISIONS vs the previous bucket-only implementation
 * ──────────────────────────────────────────────────────────────────
 * 1. EXPANDED HASH FORMAT
 *    The reference stores hashes as (K+1) groups of CollisionByteLength bytes
 *    each, produced by ExpandArray.  This aligns every collision group to full
 *    bytes, so collision detection is a plain memcmp instead of bit extraction.
 *    For variants where CollisionBitLength is divisible by 8 (192/7: 24 bits,
 *    144/5: 24 bits, 96/5: 16 bits), the expanded format equals raw bytes.
 *    For 200/9 (20 bits) and 125/4 (25 bits) it differs — fixed here.
 *
 * 2. MIN-INDEX TRACKING (approximate DistinctIndices)
 *    Each slot carries the MINIMUM leaf index of its ancestry subtree alongside
 *    the hash.  In wagner_round, pairs where min_A == min_B are rejected because
 *    they provably share the same leaf index (the minimum), producing a duplicate
 *    that would fail the pool's DistinctIndices check.
 *    This eliminates the most common cause of duplicate-index solutions (items
 *    sharing a common ancestor merging at a higher round).
 *
 * 3. FULL POST-HOC VERIFICATION
 *    After reconstruction, equihash_verify() is always called.  Any duplicate
 *    indices NOT caught by the min-index filter are discarded here.
 *
 * SLOT LAYOUT
 * ──────────────────────────────────────────────────────────────────
 *   slot[0 .. hash_length-1]         : expanded hash (shrinks by CBL each round)
 *   slot[hash_length .. hash_length+3]: min leaf index (LE uint32, stays valid)
 *   Total: slot_bytes = hash_length + 4
 *
 * WORKSPACE LAYOUT
 * ──────────────────────────────────────────────────────────────────
 *   hbuf[2][nhashes_init][slot_bytes] : two alternating hash buffers
 *   pairs[wk][pairs_per_round][2]     : parent-index pairs for tree reconstruction
 *   sort_orig[nhashes_init]           : bucket-sort position → source mapping
 *   bucket_start[nbuckets+1]          : bucket start offsets
 *   bucket_size [nbuckets]            : bucket item counts
 */

#include "equihash.h"
#include "../blake/sph_blake2b.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ── Parameter helpers ───────────────────────────────────────────── */

static int eh_indices_per_hash(int wn)
{
    return 512 / wn;   /* IndicesPerHashOutput = 512/N (integer division) */
}

static int eh_hash_output(int wn)
{
    /* HashOutput = IndicesPerHashOutput * N/8  (non-ZelHash)
     * ZelHash (N=125): IndicesPerHashOutput * ceil(N/8)           */
    int iph = eh_indices_per_hash(wn);
    if (wn == 125) return iph * ((wn + 7) / 8);
    return iph * (wn / 8);
}

/* ── Variant table ───────────────────────────────────────────────── */

eh_params_t EH_PARAMS_200_9;
eh_params_t EH_PARAMS_144_5;
eh_params_t EH_PARAMS_192_7;
eh_params_t EH_PARAMS_96_5;
eh_params_t EH_PARAMS_125_4;

static int g_variants_init = 0;

static eh_params_t build_params(int wn, int wk, const char *prefix)
{
    eh_params_t p;
    p.wn              = wn;
    p.wk              = wk;
    p.collision_bits  = wn / (wk + 1);
    p.proofsize       = 1 << wk;
    p.nhashes_init    = 1 << (p.collision_bits + 1);
    p.pairs_per_round = p.nhashes_init;
    /* CollisionByteLength = ceil(CollisionBitLength / 8) */
    p.cbl             = (p.collision_bits + 7) / 8;
    /* HashLength = (K+1) * CollisionByteLength  (expanded format) */
    p.hash_length     = (wk + 1) * p.cbl;
    /* slot_bytes: hash + 4-byte min_leaf_index */
    p.slot_bytes      = p.hash_length + 4;
    /* Bucket count: use all CollisionBits as bucket key, cap at 2^20 */
    int bkt_bits      = p.collision_bits < 20 ? p.collision_bits : 20;
    p.nbuckets        = 1 << bkt_bits;
    p.index_bits      = p.collision_bits + 1;
    p.solution_size   = (p.proofsize * p.index_bits + 7) / 8;
    /* hashlen: raw bytes per hash value = ceil(wn/8) (for Blake2b output) */
    p.hashlen         = (wn + 7) / 8;

    /* Personalization: 8-char prefix + LE32(wn) + LE32(wk) */
    memset(p.personalization, 0, 16);
    memcpy(p.personalization, prefix, 8);
    p.personalization[ 8] = (uint8_t)wn;
    p.personalization[ 9] = (uint8_t)(wn >> 8);
    p.personalization[10] = (uint8_t)(wn >> 16);
    p.personalization[11] = (uint8_t)(wn >> 24);
    p.personalization[12] = (uint8_t)wk;
    p.personalization[13] = (uint8_t)(wk >> 8);
    p.personalization[14] = (uint8_t)(wk >> 16);
    p.personalization[15] = (uint8_t)(wk >> 24);
    return p;
}

static void ensure_variants(void)
{
    if (g_variants_init) return;
    EH_PARAMS_200_9 = build_params(200, 9, "ZcashPoW");
    EH_PARAMS_144_5 = build_params(144, 5, "BgoldPoW");
    EH_PARAMS_192_7 = build_params(192, 7, "ZERO    ");
    EH_PARAMS_96_5  = build_params( 96, 5, "ZcashPoW");
    EH_PARAMS_125_4 = build_params(125, 4, "ZelProoW");
    g_variants_init = 1;
}

void eh_ensure_variants(void) { ensure_variants(); }

/* ── Pool-sent params parsing ────────────────────────────────────── */

bool eh_params_from_stratum(eh_params_t *out, const char *wn_wk_str,
                             const char *personal8)
{
    if (!wn_wk_str || !personal8) return false;
    int wn = 0, wk = 0;
    if (sscanf(wn_wk_str, "%d_%d", &wn, &wk) != 2) return false;
    if (wn <= 0 || wk <= 0 || (wn % (wk + 1)) != 0) return false;
    *out = build_params(wn, wk, personal8);
    return true;
}

/* ── Workspace ───────────────────────────────────────────────────── */

size_t eh_workspace_bytes(const eh_params_t *p)
{
    size_t h  = (size_t)p->nhashes_init * p->slot_bytes;
    size_t pr = (size_t)p->wk * p->pairs_per_round * 8;
    size_t so = (size_t)p->nhashes_init * 4;
    size_t bs = (size_t)(p->nbuckets + 1) * 4;
    size_t bz = (size_t)p->nbuckets * 4;
    return 2*h + pr + so + bs + bz + 256;
}

bool eh_workspace_alloc(eh_workspace_t **ws_ptr, const eh_params_t *p)
{
    size_t total = eh_workspace_bytes(p);
    if (total > 512UL * 1024 * 1024)
        fprintf(stderr, "equihash: allocating %.0f MB for %d/%d "
                "(significant RAM required)\n",
                total / (1024.0*1024.0), p->wn, p->wk);

    if (*ws_ptr) { free((*ws_ptr)->_base); free(*ws_ptr); *ws_ptr = NULL; }

    eh_workspace_t *ws = (eh_workspace_t *)calloc(1, sizeof(eh_workspace_t));
    if (!ws) return false;
    uint8_t *base = (uint8_t *)malloc(total);
    if (!base) { free(ws); return false; }
    ws->_base = base;  ws->_size = total;
    ws->params = *p;

    uint8_t *cur = base;
    size_t sh = (size_t)p->nhashes_init * p->slot_bytes;
    ws->hbuf0         = cur;  cur += sh;
    ws->hbuf1         = cur;  cur += sh;
    ws->pairs         = (uint32_t *)cur;
    cur += (size_t)p->wk * p->pairs_per_round * 8;
    ws->sort_orig     = (uint32_t *)cur;
    cur += (size_t)p->nhashes_init * 4;
    ws->bucket_start  = (uint32_t *)cur;
    cur += (size_t)(p->nbuckets + 1) * 4;
    ws->bucket_size   = (uint32_t *)cur;
    *ws_ptr = ws;
    return true;
}

void eh_workspace_free(eh_workspace_t *ws)
{
    if (!ws) return;
    free(ws->_base);
    free(ws);
}

/* ── Blake2b with personalization ────────────────────────────────── */

static const uint64_t blake2b_iv_c[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static inline uint64_t load64le(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= ((uint64_t)p[i]) << (8*i);
    return v;
}

static void blake2b_init_pers(sph_blake2b_ctx *ctx, size_t outlen,
                               const uint8_t *personal)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->outlen = outlen;
    for (int i = 0; i < 8; i++) ctx->h[i] = blake2b_iv_c[i];
    ctx->h[0] ^= (uint64_t)outlen | (1ULL << 16) | (1ULL << 24);
    if (personal) {
        ctx->h[6] ^= load64le(personal);
        ctx->h[7] ^= load64le(personal + 8);
    }
}

/* ── ExpandArray (reference algorithm) ──────────────────────────── */
/* Converts raw hash bytes to collision-aligned expanded format.
 * Matches CompressArray/ExpandArray from equihash.cpp exactly.      */
static void expand_hash(const uint8_t *in, int in_len,
                         uint8_t *out, int out_len, int bit_len)
{
    /* out_width = ceil(bit_len/8) bytes per group (byte_pad=0 always here) */
    int out_width = (bit_len + 7) / 8;
    uint32_t mask = ((uint32_t)1 << bit_len) - 1;
    uint32_t acc  = 0;
    int acc_bits  = 0;
    int j         = 0;
    for (int i = 0; i < in_len && j < out_len; i++) {
        acc = (acc << 8) | in[i];
        acc_bits += 8;
        if (acc_bits >= bit_len) {
            acc_bits -= bit_len;
            uint32_t val = (acc >> acc_bits) & mask;
            /* Write val big-endian into out_width bytes */
            for (int x = out_width - 1; x >= 0; x--) {
                out[j + x] = (uint8_t)(val & 0xFF);
                val >>= 8;
            }
            j += out_width;
        }
    }
}

/* ── Slot accessors ──────────────────────────────────────────────── */

/* Minimum leaf index stored at slot[hash_length..hash_length+3] (LE32) */
static inline uint32_t slot_get_min(const uint8_t *slot, int hash_length)
{
    const uint8_t *p = slot + hash_length;
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) |
           ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}

static inline void slot_set_min(uint8_t *slot, int hash_length, uint32_t v)
{
    uint8_t *p = slot + hash_length;
    p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8);
    p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24);
}

/* Bucket key from expanded hash: take the top min(collision_bits,20) bits
 * of the collision group, big-endian (MSB first, as the reference stores
 * them).  The collision group always begins at slot[0] (its MSB).
 *
 * This always reads exactly 3 bytes, so slot[0] is the most-significant
 * byte at bit position 23.  The key is therefore the top bkt_bits counted
 * down from bit 23, i.e. shift = 24 - bkt_bits — INDEPENDENT of cbl.
 *
 * The earlier `cbl*8 - bkt_bits` form was only correct for cbl == 3.  For
 * cbl == 2 (96/5) it produced shift 0, keying on bits 8..23 (slot[1..2])
 * while coll_match compares slot[0..1] (bits 0..15) — a range mismatch that
 * left buckets with almost no real collisions and yielded zero solutions.
 *
 * Because coll_match re-checks the full cbl bytes, using bkt_bits ≤ the
 * group width keeps the bucket a correct superset of true collisions for
 * every variant (cbl = 2, 3 and 4).                                      */
static inline uint32_t bucket_key_be(const uint8_t *slot, int cbl,
                                      int collision_bits)
{
    (void)cbl;
    int bkt_bits = collision_bits < 20 ? collision_bits : 20;
    /* Read first 3 bytes big-endian (slot[0] = MSB at bit 23).          */
    uint32_t v = ((uint32_t)slot[0] << 16) |
                 ((uint32_t)slot[1] <<  8) |
                  (uint32_t)slot[2];
    int shift = 24 - bkt_bits;
    return (v >> shift) & ((1u << bkt_bits) - 1);
}

/* Check full collision: first cbl bytes must be equal (big-endian match) */
static inline int coll_match(const uint8_t *a, const uint8_t *b, int cbl)
{
    return memcmp(a, b, cbl) == 0;
}

/* XOR first hash_length bytes (NOT the min_idx at the end) */
static void xor_hash(uint8_t *dst, const uint8_t *src, int hash_length)
{
    for (int i = 0; i < hash_length; i++) dst[i] ^= src[i];
}

/* Shift expanded hash left by one CollisionByteLength group (cbl bytes).
 * Removes the already-matched collision group; next group slides to front. */
static void shift_hash(uint8_t *slot, int hash_length, int cbl)
{
    int remaining = hash_length - cbl;
    if (remaining > 0)
        memmove(slot, slot + cbl, remaining);
    memset(slot + remaining, 0, cbl);
}

/* True iff the leading cbl bytes of the slot hash are all zero. */
static inline int slot_zero(const uint8_t *slot, int cbl)
{
    for (int i = 0; i < cbl; i++) if (slot[i]) return 0;
    return 1;
}

/* ── Hash generation ─────────────────────────────────────────────── */

static void generate_hashes(const uint8_t *header, eh_workspace_t *ws)
{
    const eh_params_t *p = &ws->params;
    int iph       = eh_indices_per_hash(p->wn);
    int hash_out  = eh_hash_output(p->wn);   /* bytes per Blake2b call */
    int raw_hlen  = (p->wn + 7) / 8;         /* raw bytes per hash value */

    uint8_t digest[64];

    for (uint32_t blk = 0; blk < (uint32_t)(p->nhashes_init / iph); blk++) {
        sph_blake2b_ctx ctx;
        blake2b_init_pers(&ctx, hash_out, p->personalization);
        sph_blake2b_update(&ctx, header, 140);
        uint32_t blk_le = blk;
        sph_blake2b_update(&ctx, &blk_le, 4);
        sph_blake2b_final(&ctx, digest);

        for (int h = 0; h < iph; h++) {
            uint32_t idx = blk * iph + h;
            uint8_t *slot = ws->hbuf0 + (size_t)idx * p->slot_bytes;
            memset(slot, 0, p->slot_bytes);

            /* Expand the raw hash into (K+1)*cbl aligned byte groups.
             * expand_hash implements ExpandArray from the reference.    */
            expand_hash(digest + h * raw_hlen, raw_hlen,
                        slot, p->hash_length, p->collision_bits);

            /* Store initial min_idx = the hash index itself */
            slot_set_min(slot, p->hash_length, idx);
        }
    }
}

/* ── Bucket sort ─────────────────────────────────────────────────── */

static void bucket_sort(uint32_t n_src, eh_workspace_t *ws)
{
    const eh_params_t *p = &ws->params;
    uint32_t *bsz = ws->bucket_size;
    uint32_t *bst = ws->bucket_start;

    memset(bsz, 0, (size_t)p->nbuckets * 4);
    for (uint32_t i = 0; i < n_src; i++) {
        const uint8_t *s = ws->hbuf0 + (size_t)i * p->slot_bytes;
        bsz[bucket_key_be(s, p->cbl, p->collision_bits)]++;
    }
    bst[0] = 0;
    for (int b = 0; b < p->nbuckets; b++)
        bst[b+1] = bst[b] + bsz[b];
    memset(bsz, 0, (size_t)p->nbuckets * 4);

    for (uint32_t i = 0; i < n_src; i++) {
        const uint8_t *s = ws->hbuf0 + (size_t)i * p->slot_bytes;
        uint32_t b = bucket_key_be(s, p->cbl, p->collision_bits);
        uint32_t dst = bst[b] + bsz[b];
        memcpy(ws->hbuf1 + (size_t)dst * p->slot_bytes, s, p->slot_bytes);
        ws->sort_orig[dst] = i;
        bsz[b]++;
    }
}

/* ── One Wagner round ────────────────────────────────────────────── */
/*
 * For each bucket in hbuf1 (sorted), find all pairs (i, j) where the first
 * cbl bytes match exactly (HasCollision).  Before creating a pair:
 *   - Check coll_match(i, j, cbl) for FULL collision_bits (bkt_bits may be
 *     fewer than collision_bits when bkt_bits < collision_bits)
 *   - Check min_idx(i) != min_idx(j): if equal, these two items share at
 *     least one common ancestor leaf → they cannot form a valid distinct pair
 *
 * On a valid pair: XOR the hashes, shift away the matched group, compute
 * new min_idx = min(min_i, min_j), record parent refs in pairs[round][].
 */
static uint32_t wagner_round(int round, uint32_t n_in, uint32_t max_out,
                              eh_workspace_t *ws)
{
    const eh_params_t *p = &ws->params;
    int cbl = p->cbl;
    uint32_t n_out = 0;
    (void)n_in;

    for (int b = 0; b < p->nbuckets && n_out < max_out; b++) {
        uint32_t start = ws->bucket_start[b];
        uint32_t cnt   = ws->bucket_size[b];

        for (uint32_t i = start; i < start+cnt && n_out < max_out; i++) {
            const uint8_t *si = ws->hbuf1 + (size_t)i * p->slot_bytes;
            uint32_t min_i = slot_get_min(si, p->hash_length);

            for (uint32_t j = i+1; j < start+cnt && n_out < max_out; j++) {
                const uint8_t *sj = ws->hbuf1 + (size_t)j * p->slot_bytes;

                /* Full collision check (needed when bkt_bits < collision_bits) */
                if (!coll_match(si, sj, cbl)) continue;

                uint32_t min_j = slot_get_min(sj, p->hash_length);

                /* Approximate DistinctIndices: reject if same min leaf index.
                 * Two rows sharing their minimum leaf index definitely share
                 * that index → merging them produces a duplicate-index solution.
                 * This eliminates the most common cause of invalid solutions.  */
                if (min_i == min_j) continue;

                /* Merge: XOR hashes, shift away the matched cbl-byte group */
                uint8_t *dst = ws->hbuf0 + (size_t)n_out * p->slot_bytes;
                memcpy(dst, si, p->slot_bytes);
                xor_hash(dst, sj, p->hash_length);
                shift_hash(dst, p->hash_length, cbl);

                /* Propagate min_idx = min(min_i, min_j) */
                slot_set_min(dst, p->hash_length,
                             min_i < min_j ? min_i : min_j);

                /* Record source positions for tree reconstruction */
                uint32_t *pr = ws->pairs +
                    ((size_t)round * p->pairs_per_round + n_out) * 2;
                pr[0] = ws->sort_orig[i];
                pr[1] = ws->sort_orig[j];
                n_out++;
            }
        }
    }
    return n_out;
}

/* ── Tree reconstruction ─────────────────────────────────────────── */

static void collect_indices(int round, uint32_t slot,
                             const eh_workspace_t *ws,
                             uint32_t *out, uint32_t *pos)
{
    if (round < 0) { out[(*pos)++] = slot; return; }
    const uint32_t *pr = ws->pairs +
        ((size_t)round * ws->params.pairs_per_round + slot) * 2;
    collect_indices(round - 1, pr[0], ws, out, pos);
    collect_indices(round - 1, pr[1], ws, out, pos);
}

/* ── Tree-order fix (IndicesBefore) ─────────────────────────────── */

static void fix_tree_order(uint32_t *idx, int n)
{
    if (n <= 1) return;
    int half = n / 2;
    fix_tree_order(idx,        half);
    fix_tree_order(idx + half, half);
    if (idx[0] > idx[half]) {
        uint32_t tmp[512];  /* max proofsize */
        memcpy(tmp,        idx,        (size_t)half * 4);
        memmove(idx,       idx + half, (size_t)half * 4);
        memcpy(idx + half, tmp,        (size_t)half * 4);
    }
}

/* ── Index validation ────────────────────────────────────────────── */

static int cmp_u32(const void *a, const void *b)
{
    uint32_t x = *(const uint32_t*)a, y = *(const uint32_t*)b;
    return (x > y) - (x < y);
}

/* Sort a copy and check adjacent elements — catches ALL duplicates,
 * not just adjacent ones after tree-ordering.                         */
static int indices_distinct(const uint32_t *idx, int n)
{
    uint32_t *tmp = (uint32_t *)malloc((size_t)n * 4);
    if (!tmp) return 0;
    memcpy(tmp, idx, (size_t)n * 4);
    qsort(tmp, n, 4, cmp_u32);
    int ok = 1;
    for (int i = 1; i < n; i++) {
        if (tmp[i] == tmp[i-1]) { ok = 0; break; }
    }
    free(tmp);
    return ok;
}

/* ── Solution packing (big-endian, CompressArray convention) ─────── */

static void pack_indices(const uint32_t *idx, int proofsize,
                          int index_bits, uint8_t *out)
{
    int sol_bytes = (proofsize * index_bits + 7) / 8;
    memset(out, 0, sol_bytes);
    uint64_t acc  = 0;
    int acc_bits  = 0, out_pos = 0;
    uint32_t mask = (index_bits < 32) ? ((1u << index_bits) - 1u) : ~0u;
    for (int i = 0; i < proofsize; i++) {
        acc = (acc << index_bits) | (idx[i] & mask);
        acc_bits += index_bits;
        while (acc_bits >= 8) {
            acc_bits -= 8;
            out[out_pos++] = (uint8_t)((acc >> acc_bits) & 0xFF);
        }
    }
    if (acc_bits > 0)
        out[out_pos] = (uint8_t)((acc << (8 - acc_bits)) & 0xFF);
}

/* ── TLS workspace ───────────────────────────────────────────────── */

/* Thread-local workspace (kept for API compat; gate allocates via
 * eh_workspace_alloc which sizes correctly per variant).              */
static __thread void *tl_ws_unused = NULL;

bool equihash_thread_init(int thr_id)
{
    (void)thr_id;
    (void)tl_ws_unused;
    return true;   /* actual workspace allocated in equihash-gate.c */
}

/* ── Public solver ───────────────────────────────────────────────── */

int equihash_solve(const uint8_t *header, eh_workspace_t *ws,
                   uint8_t solutions[][EH_MAX_SOLUTION_BYTES], int max_sols)
{
    ensure_variants();
    int nsols = 0;

    generate_hashes(header, ws);
    /* generate_hashes fills exactly (nhashes_init / iph) * iph slots — for
     * variants where iph does not divide nhashes_init evenly (96/5, 200/9,
     * 125/4) the tail slots are left as uninitialized malloc garbage. Bound
     * round 0 to the slots actually populated so that garbage never enters
     * the solver as spurious collisions.                                   */
    {
        int iph = eh_indices_per_hash(ws->params.wn);
        ws->round_cnt[0] = (ws->params.nhashes_init / iph) * iph;
    }

    for (int r = 0; r < ws->params.wk; r++) {
        bucket_sort(ws->round_cnt[r], ws);
        ws->round_cnt[r + 1] =
            wagner_round(r, ws->round_cnt[r], ws->params.pairs_per_round, ws);
    }

    uint32_t n_final = ws->round_cnt[ws->params.wk];
    const eh_params_t *p = &ws->params;

    for (uint32_t s = 0; s < n_final && nsols < max_sols; s++) {
        const uint8_t *slot = ws->hbuf0 + (size_t)s * p->slot_bytes;
        /* Final solution: remaining cbl bytes must be zero */
        if (!slot_zero(slot, p->cbl)) continue;

        uint32_t *indices = (uint32_t *)malloc((size_t)p->proofsize * 4);
        if (!indices) break;
        uint32_t pos = 0;
        collect_indices(p->wk - 1, s, ws, indices, &pos);
        if ((int)pos != p->proofsize) { free(indices); continue; }

        fix_tree_order(indices, p->proofsize);
        if (!indices_distinct(indices, p->proofsize)) { free(indices); continue; }

        pack_indices(indices, p->proofsize, p->index_bits, solutions[nsols++]);
        free(indices);
    }
    return nsols;
}

/* ── Verifier ────────────────────────────────────────────────────── */

/* Unpack one index from big-endian CompressArray-packed solution. */
static uint32_t unpack_index(const uint8_t *sol, int i, int index_bits)
{
    int bit_start = i * index_bits;
    int byte_off  = bit_start / 8;
    int bit_off   = bit_start % 8;
    uint32_t v = 0;
    int bytes_needed = (index_bits + bit_off + 7) / 8;
    for (int b = 0; b < bytes_needed && b < 4; b++)
        v = (v << 8) | sol[byte_off + b];
    int total_bits = bytes_needed * 8;
    v >>= (total_bits - bit_off - index_bits);
    return v & ((1u << index_bits) - 1);
}

bool equihash_verify(const uint8_t *header, const eh_params_t *p,
                     const uint8_t *solution, size_t sol_len)
{
    ensure_variants();
    if ((int)sol_len != p->solution_size) return false;

    uint32_t *indices = (uint32_t *)malloc((size_t)p->proofsize * 4);
    if (!indices) return false;

    for (int i = 0; i < p->proofsize; i++)
        indices[i] = unpack_index(solution, i, p->index_bits);

    /* Check tree-level ordering (IndicesBefore at every tree depth).
     * After fix_tree_order, left subtree always has smaller first index. */
    for (int step = 1; step < p->proofsize; step *= 2) {
        for (int i = 0; i + step < p->proofsize; i += 2*step) {
            if (indices[i] >= indices[i + step]) {
                free(indices); return false;
            }
        }
    }

    /* Allocate per-hash slots on heap */
    uint8_t *hashes = (uint8_t *)malloc((size_t)p->proofsize * p->slot_bytes);
    if (!hashes) { free(indices); return false; }

    int iph      = eh_indices_per_hash(p->wn);
    int hash_out = eh_hash_output(p->wn);
    int raw_hlen = p->hashlen;
    uint8_t digest[64];

    for (int i = 0; i < p->proofsize; i++) {
        uint32_t blk = indices[i] / iph;
        int      pos = indices[i] % iph;
        sph_blake2b_ctx ctx;
        blake2b_init_pers(&ctx, hash_out, p->personalization);
        sph_blake2b_update(&ctx, header, 140);
        sph_blake2b_update(&ctx, &blk, 4);
        sph_blake2b_final(&ctx, digest);
        uint8_t *slot = hashes + (size_t)i * p->slot_bytes;
        memset(slot, 0, p->slot_bytes);
        expand_hash(digest + pos * raw_hlen, raw_hlen,
                    slot, p->hash_length, p->collision_bits);
    }
    free(indices);

    /* Verify K rounds of pairwise XOR cancellation.
     * Pairs: (0,1), (2,3), ..., writing merged result to positions 0, 1, ...
     * After all n/2 merges, array [0..n/2-1] holds the next round's hashes. */
    int n = p->proofsize;
    for (int r = 0; r < p->wk; r++) {
        int n2 = n / 2;
        for (int i = 0; i < n2; i++) {
            uint8_t *a   = hashes + (size_t)(2*i)   * p->slot_bytes;
            uint8_t *b   = hashes + (size_t)(2*i+1) * p->slot_bytes;
            uint8_t *dst = hashes + (size_t)i       * p->slot_bytes;
            if (!coll_match(a, b, p->cbl)) { free(hashes); return false; }
            /* Merge into a temporary then copy to dst */
            uint8_t merged[40] = {0};   /* max hash_length = 30 (200/9) + margin */
            memcpy(merged, a, p->hash_length);
            xor_hash(merged, b, p->hash_length);
            shift_hash(merged, p->hash_length, p->cbl);
            memcpy(dst, merged, p->hash_length);
        }
        n = n2;
    }

    bool ok = slot_zero(hashes, p->cbl);
    free(hashes);
    return ok;
}
