# SHA3T (SHA3-256t)

**Coins:** BitcoinIII (BC3), Fjarcode (FJAR)
**Algorithm name:** `sha3t` (alias: `sha3-256t`, the pool-side name)
**Family:** iterated single-primitive hash

```
./cpuminer -a sha3t -o stratum+tcp://<pool>:<port> -u <wallet> -p x
```

---

## Overview

SHA3-256t is NIST SHA3-256 applied three times to the 80-byte block header:

```
hash = SHA3-256( SHA3-256( SHA3-256( header80 ) ) )
```

That is the entire algorithm. It uses the standard Bitcoin-style Stratum flow (80-byte
header, 32-bit nonce) and an unmodified Bitcoin difficulty scale, so the share target
needs no scaling factor.

BitcoinIII is Bitcoin Core with exactly one consensus change: the block hash *and* the
proof-of-work hash are SHA3-256t instead of SHA-256d. Because the block hash is the PoW
hash, a published BC3 block hash is a ready-made test vector — see *Verification*.

The design goal is ASIC/rental resistance by novelty rather than by cost: there is no
SHA3-256t rental-hashrate market, so an attacker cannot rent compatible hashpower.

## Padding: SHA3, not Keccak

The primitive is **NIST FIPS 202 SHA3-256** (domain separation byte `0x06`), not the
pre-standard Keccak-256 (`0x01`) that Ethereum and `-a keccak` use. Getting this wrong
changes every digest. In this tree the selector is the global `hard_coded_eb`, which
`register_sha3t_algo` sets to `6`.

## ⚠️ Merkle root: sha3t is *not* sha3d

`sha3d` overrides the Stratum merkle-root construction to hash the coinbase with `sha3d`.
**`sha3t` does not** — it uses the ordinary `sha256d` merkle root, like Bitcoin. The two
algorithms are one character apart in the name and take opposite answers here.

Getting this wrong is silent: the startup KAT still passes (the hash function is right),
the miner reports a healthy hashrate, and the pool rejects every share as invalid. If you
see "Invalid share" with a passing KAT, look at the merkle root before the hash.

This is settled from chain data, not from the coin's name. Recomputing the merkle root of
BC3 blocks 44172 (4 tx), 39663 (2 tx) and 53000 (2 tx) from their transaction ids
reproduces each header's `merkleroot` field exactly with `sha256d`, and produces an
unrelated value with `sha3d`.

## Implementation

| Path | Width | Requires |
|---|---|---|
| `scanhash_sha3t_8way` | 8 nonces | AVX-512 |
| `scanhash_sha3t_4way` | 4 nonces | AVX2 |
| `scanhash_sha3t_2x64` | 2 nonces | SSE2 or NEON |
| `scanhash_sha3t` | 1 nonce | scalar C |

The batched paths reuse the shared n-way Keccak cores in `algo/keccak/`, so `sha3t`
shipped batched from the start rather than scalar-first. Note that the scalar and batched
loops use different nonce conventions, inherited from `sha3d`/`keccak` — see the comment
at the top of `sha3t-4way.c` before writing any 1-way vs n-way comparison.

## Verification

A known-answer test runs at startup and **refuses to mine on mismatch**. Because a BC3
block hash *is* the sha3t digest of its header, the vectors are two real mainnet block
headers — **44172** and **39663** — rather than synthetic inputs, so they pin the
algorithm to the live chain's consensus, not just to another implementation.

Both are post-fork blocks: BC3 selects the block-hash algorithm on version bit 12 and
only sets it from height 30240 on, so a pre-fork block hashes with SHA-256d and is
useless as an anchor.

On builds with a batched path, the KAT anchors the scalar reference and the batched path
is then compared against it lane-by-lane over 64 randomised headers, so every lane and
the interleave/extract plumbing are covered too.

End-to-end correctness is confirmed by pool-accepted shares: **18 submitted, 18 accepted,
0 rejected** across two block changes. That is the part a KAT cannot prove — the merkle
root is built by the Stratum layer, not by the hash function, so only a live pool can
rule out the trap described above.

## Possible optimizations (preview)

The hash is three Keccak-f[1600] permutations and nothing else, and all three already run
at the widest available lane. Remaining candidates are small:

- **First-permutation precompute.** 72 of the 80 header bytes are constant across nonces,
  so the first absorb can be partially folded per job. Worthwhile on GPUs; on CPU it is
  one absorb out of three permutations, so the ceiling is low.
- **Target prefilter.** The algorithm is fast enough that per-nonce loop overhead is a
  meaningful fraction of runtime; the existing `hash7 <= Htarg` prefilter already handles
  the common case.
