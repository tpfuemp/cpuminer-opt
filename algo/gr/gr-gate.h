#ifndef GR_GATE_H__
#define GR_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

// Consensus GhostRider (Raptoreum) hash: 15 core rounds (x16 set minus SHA)
// interleaved with 3 of 6 CryptoNight-v1 variants, both orders derived from
// the block header. `output` receives 32 bytes.
void gr_hash( void *output, const void *input );

// Known-answer self-test; returns true on success. Run once per process.
bool gr_self_test( void );

int scanhash_gr( struct work *work, uint32_t max_nonce, uint64_t *hashes_done,
                 struct thr_info *mythr );

bool register_gr_algo( algo_gate_t *gate );

#endif /* GR_GATE_H__ */
