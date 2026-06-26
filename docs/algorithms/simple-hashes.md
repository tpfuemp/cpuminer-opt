# Simple & legacy hashes

**Family:** single-hash and short fixed-chain proof-of-work algorithms
**Algorithm names:** `sha256d`, `sha256t`, `sha256q`, `sha256dt`, `sha512256d`,
`sha3d`, `keccak`, `keccakc`, `blake`, `blakecoin`, `vanilla`, `blake2s`, `blake2b`,
`pentablake`, `bmw`, `bmw512`, `groestl`, `dmd-gr`, `myr-gr`, `skein`, `skein2`,
`whirlpool`, `whirlpoolx`, `nist5`, `quark`, `qubit`, `anime`

```
./cpuminer -a sha256d -o stratum+tcp://<pool>:<port> -u <wallet> -p x
```

---

## Overview

These are the conventional algorithms: one well-known hash applied once or a few
times, or a short fixed chain of a handful of hashes. They predate the long X-chains
and the memory-hard designs, and they all use the standard Bitcoin-style Stratum flow
(80-byte header, 32-bit nonce). Because they are mostly a single primitive, they are
the most thoroughly SIMD-optimized algorithms in the project.

## SHA-2 / SHA-3 lineage

| Algo | Definition | Notes |
|---|---|---|
| `sha256d` | SHA-256 applied twice | Bitcoin's algorithm |
| `sha256t` | SHA-256 applied three times | |
| `sha256q` | SHA-256 applied four times | |
| `sha256dt` | double SHA-256 with a **custom initialization vector** | |
| `sha512256d` | double SHA-512/256 (SHA-512 truncated to 256 bits) | |
| `sha3d` | double Keccak-256 (SHA-3 padding) | BSHA3 |

(Veil's `sha256dv` is a SHA-256d variant with its own Stratum protocol — see
[SHA256Dv](sha256dv.md).)

## Keccak

| Algo | Definition | Coin |
|---|---|---|
| `keccak` | Keccak-256 | Maxcoin |
| `keccakc` | Keccak-256 (SHA-3 padding variant) | Creative Coin |

## BLAKE

| Algo | Definition | Coin |
|---|---|---|
| `blake` | BLAKE-256, 14 rounds | |
| `blakecoin` | BLAKE-256, 8 rounds | |
| `vanilla` | BLAKE-256, 8 rounds (vanilla variant) | VCash |
| `blake2s` | BLAKE2s-256 | |
| `blake2b` | BLAKE2b-512 | |
| `pentablake` | BLAKE-512 applied five times | Pentablake |

## Groestl

| Algo | Definition | Coin |
|---|---|---|
| `groestl` | Groestl-512 | Groestlcoin |
| `dmd-gr` | Diamond-Groestl | Diamond |
| `myr-gr` | Groestl-512 + SHA-256 ("Myriad-Groestl") | Myriad |

## Skein / BMW / Whirlpool

| Algo | Definition | Coin |
|---|---|---|
| `skein` | Skein-512 + SHA-256 | Skeincoin |
| `skein2` | Skein-512 applied twice | Woodcoin |
| `bmw` | BMW-256 | |
| `bmw512` | BMW-512 | |
| `whirlpool` | Whirlpool | |
| `whirlpoolx` | Whirlpool variant | |

## Short fixed chains

A handful of hashes in a fixed order — the small ancestors of the X-chains:

| Algo | Chain | Coin |
|---|---|---|
| `nist5` | blake, groestl, jh, keccak, skein (the 5 SHA-3 finalists) | |
| `quark` | blake, bmw, groestl, jh, keccak, skein with **data-dependent branching** (9 steps) | Quarkcoin |
| `qubit` | luffa, cubehash, shavite, simd, echo | Qubit |
| `anime` | a Quark variant with different branching | Animecoin |

## Performance

- **SHA-NI** for the SHA-256 algorithms, and wide multi-way SHA-256 (8/16-way on
  AVX2/AVX-512) for scanning many nonces per pass.
- **AES-NI / VAES** for Groestl and Whirlpool rounds.
- **Parallel-lane hashing** (4/8/16-way) for the BLAKE, BMW, Keccak, Skein and
  short-chain algorithms.
- **Midstate caching** where the first hash's leading block is constant across nonces.

## Verification

Every SIMD width matches the scalar reference byte-for-byte; correctness is confirmed
by pool-accepted shares.

## Possible optimizations (preview)

These are mature and close to optimal. Remaining candidates are incremental:

- **Full AVX-512 / VAES coverage** — make sure every algorithm has the widest lane and
  hardware-AES path on capable CPUs.
- **Target prefilter** — for the multi-hash members (`sha256t/q`, `nist5`, `quark`),
  skip the remaining rounds once an intermediate value cannot meet the target.
