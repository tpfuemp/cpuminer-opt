#ifndef SKYDOGE_GATE_H__
#define SKYDOGE_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

// SkyDoge width dispatch. Phase 2b starts with the 4x64 path, enabled on AVX2
// and above (so AVX-512 also exercises it for now); wider 8x64/16-way paths can
// be added later. SSE2/NEON and non-AVX2 builds use the scalar path.
#if defined(__AVX2__)
  #define SKYDOGE_4WAY 1
#endif

bool register_skydoge_algo( algo_gate_t *gate );

// Scalar reference path (always compiled; also the consensus reference).
int  skydoge_hash( void *output, const void *input, int thr_id );
int  scanhash_skydoge( struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done, struct thr_info *mythr );
bool skydoge_self_test( void );

// Consensus KAT (from a pool-accepted share), shared by both paths' self-tests.
extern const uint8_t skydoge_test_input[80];
extern const uint8_t skydoge_test_expected[32];

#if defined(SKYDOGE_4WAY)
int  skydoge_4x64_hash( void *output, const void *input, int thr_id );
int  scanhash_skydoge_4x64( struct work *work, uint32_t max_nonce,
                            uint64_t *hashes_done, struct thr_info *mythr );
bool skydoge_4way_self_test( void );
#endif

#endif // SKYDOGE_GATE_H__
