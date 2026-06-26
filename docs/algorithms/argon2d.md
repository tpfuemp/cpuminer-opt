# Argon2d family

**Coins:** Credits (CRDS), Dynamic (DYN), Unitus (UIS), and others
**Algorithm names:** `argon2d250`, `argon2d500`, `argon2d1000`, `argon2d4096`, `argon2d16000`
**Family:** memory-hard proof-of-work (Argon2d KDF)

```
./cpuminer -a argon2d500 -o stratum+tcp://<pool>:<port> -u <wallet> -p x
```

---

## Overview

Argon2 is the winner of the Password Hashing Competition; **Argon2d** is its
data-dependent variant, where memory-access addresses depend on the data being
hashed. That dependency maximises resistance to time–memory tradeoffs (and to GPUs
and ASICs), at the cost of side-channel leakage — irrelevant for proof-of-work.

As a PoW it is straightforward: fill a buffer of `m_cost` KiB of memory, mix it for
`t_cost` passes across `lanes` parallel lanes, and emit a 32-byte tag compared
against the target. There is no chaining of other hashes and no protocol
customization — it uses the standard Bitcoin-style Stratum flow (80-byte header,
32-bit nonce at header word 19).

For every nonce the miner runs Argon2d with both the **password and salt set to the
80-byte block header** (`pwd = salt = header`), producing the 32-byte hash.

## Variants

The variants differ only in Argon2 cost parameters (and, for one, the Argon2 version
— which is consensus-critical):

| Algo | memory `m_cost` | passes `t_cost` | lanes | Argon2 version | Coin |
|---|---|---|---|---|---|
| `argon2d250`   | 250 KiB   | 1 | 4 | 1.0 | Credits (CRDS) |
| `argon2d500`   | 500 KiB   | 2 | 8 | 1.0 | Dynamic (DYN) |
| `argon2d1000`  | 1000 KiB  | 2 | 8 | 1.0 | — |
| `argon2d4096`  | 4096 KiB (4 MiB) | 1 | 1 | **1.3** | Unitus (UIS) |
| `argon2d16000` | 16000 KiB (~16 MiB) | 1 | 1 | 1.0 | — |

Notes:
- **`argon2d4096` uses Argon2 version 1.3** (`0x13`); all the others use version 1.0
  (`0x10`). The version changes the indexing/mixing, so it must match the coin — this
  is the easiest detail to get wrong.
- Higher `m_cost` means more RAM per hash. The high-memory variants (`argon2d4096`,
  `argon2d16000`) effectively cap how many threads fit in a machine's RAM.
- All variants output 32 bytes and use a target factor of 65536.

## Performance

- The Argon2 compression function (`fill_block`, built on the BLAKE2b round function)
  has SIMD implementations; the memory fill is the dominant cost.
- Throughput is bound by memory bandwidth and capacity, especially for the larger
  variants — this is the algorithm's intended property, not an inefficiency.

## Verification

Each implementation matches the reference Argon2d output for its parameter set;
correctness is confirmed by pool-accepted shares.

## Possible optimizations (preview)

- **Wider `fill_block`** — AVX-512 implementations of the Argon2 compression function
  for CPUs that support it.
- **Allocation reuse** — keep each thread's `m_cost` memory region allocated across
  nonces (and across jobs) instead of allocating per hash, to avoid page-fault and
  zeroing overhead on every attempt.
- **NUMA-aware placement** — pin each thread's memory region to its local NUMA node on
  multi-socket machines so the bandwidth-bound fill stays local.
