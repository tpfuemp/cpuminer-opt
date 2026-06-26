# Equihash family

**Coins:** Zcash, Horizen, Komodo (200/9); Flux/ZelCash (125/4); Bitcoin Gold (144/5);
ZeroClassic (192/7); and others
**Algorithm names:** `equihash`, `equihash96`, `equihash125`, `equihash144`, `equihash192`
**Family:** memory-oriented proof-of-work solver (not a hash chain)

```
./cpuminer -a equihash144 -o stratum+tcp://<pool>:<port> -u <wallet> -p x
```

---

## Overview

Equihash is different in kind from the other algorithms here: it is not a hash you
run forward, but a **solver** for a constrained instance of the generalized birthday
problem (Wagner's algorithm), built on Blake2b. A miner generates many Blake2b
outputs and searches for a set of indices whose XOR collapses to zero across `k`
collision rounds. Finding a solution is memory- and compute-intensive; **verifying
one is cheap**, which is the asymmetry that makes it a good PoW.

A valid solution, embedded in the block, is then scored by hashing the whole block
with SHA-256d and comparing against the share target.

## Variants

A variant is identified by its parameters `(n, k)`:

| Algo | n / k | Solution | Approx. workspace | Personalization | Notable coins |
|---|---|---|---|---|---|
| `equihash`    | 200 / 9 | 1344 B | ~190 MB | `ZcashPoW` | Zcash (ZEC), Horizen (ZEN), Komodo (KMD) |
| `equihash96`  | 96 / 5  | 68 B   | ~7 MB   | `ZcashPoW` | MinexCoin and other small-cap coins |
| `equihash125` | 125 / 4 | 52 B   | ~4 GB   | `ZelProoW` | Flux / ZelCash |
| `equihash144` | 144 / 5 | 100 B  | ~2.2 GB | `BgoldPoW` | Bitcoin Gold (BTG) |
| `equihash192` | 192 / 7 | 400 B  | ~3 GB   | `"ZERO    "` | ZeroClassic |

Larger `n` means larger solutions and higher memory use; `k` sets the number of
collision rounds (and the solution size, `2^k` indices). Each variant uses a Blake2b
**personalization string** (above) — the pool may also override it at runtime (see
[Stratum protocol](#stratum-protocol)).

**Coin aliases** resolve to a variant, so e.g. `-a btg` selects `equihash144` and
`-a zcash` / `-a zen` / `-a flux` select their respective variants.

> Practical note: workspace grows from ~7 MB (96/5) to several GB (144/5, 192/7,
> 125/4), and solve time grows with it — from sub-millisecond (96/5) to seconds
> (the large variants). On CPU, only **96/5** is comfortably real-time and **200/9**
> is marginal; the multi-GB variants are slow and effectively GPU/ASIC territory.
> The large variants `malloc` their workspace at startup and will not mine if the
> machine lacks the RAM.

## How it works

1. **Generator.** Blake2b (personalized for the variant) over the 140-byte block
   header expands into a table of `n`-bit strings.
2. **Solve.** Wagner's algorithm finds index sets that XOR to zero over `k` rounds.
   Each such set, after an ordering/uniqueness check, is a solution.
3. **Score.** The solution is packed (compact-size length prefix + raw bytes) and
   appended to the header; the share hash is `SHA256d(header ‖ packed_solution)`.

## Stratum protocol

Equihash uses the **Zcash-style** Stratum flow, which differs substantially from the
Bitcoin-style flow used by sha256d / X-family algorithms.

### 140-byte header (not 80), built from notify fields

There is no client-side coinbase assembly. The pool sends the header fields directly
and the miner lays them out:

| Offset | Size | Field |
|---|---|---|
| 0   | 4  | version |
| 4   | 32 | prevhash |
| 36  | 32 | merkleroot |
| 68  | 32 | reserved (finalsaplingroot) |
| 100 | 4  | ntime |
| 104 | 4  | nbits |
| 108 | 32 | nonce = `xnonce1 ‖ xnonce2 ‖ iteration` |

The `reserved`/finalsaplingroot field and the 32-byte nonce region are specific to
this protocol.

### 32-byte nonce, split pool/miner

The full nonce is 32 bytes = the pool's **extranonce1** (typically 4 bytes, from
`mining.subscribe`) followed by the **28-byte miner nonce**. The miner only searches
and submits its 28-byte portion; the pool prepends its extranonce1 when rebuilding
the header. Submitting all 32 bytes triggers an **"Invalid nonce size"** rejection.

### `mining.notify` — 8-param or 10-param

The standard (ZCash) notify has 8 parameters:

```
[ job_id, version, prevhash, merkleroot, reserved, ntime, nbits, clean_jobs ]
```

Some pools send an **extended 10-param** form that appends the variant selection and
personalization, letting one binary serve multiple variants and switch between them
without reconnecting:

```
[ …the 8 above…, "wn_wk", "personal8" ]
```

- `params[8]` = the `(n, k)` pair as `"200_9"` / `"144_5"` / `"192_7"` / `"96_5"` / `"125_4"`.
- `params[9]` = the 8-character personalization prefix, e.g. `"ZcashPoW"`, `"BgoldPoW"`.

When present, these rebuild the full 16-byte Blake2b personalization
(`personal8 ‖ LE32(n) ‖ LE32(k)`) and the solver switches variant on the next job.

### `mining.submit` carries the solution

```
mining.submit ← [ user, job_id, ntime, miner_nonce(28 B / 56 hex), solution ]
```

where `solution` is `compact_size(len) ‖ raw_solution_bytes`, hex-encoded. This is
unlike Bitcoin-style submits (which send `xnonce2 / ntime / nonce`) — here a full
solution blob is sent.

### Difficulty check

The pool scores the share as `SHA256d(header ‖ packed_solution)` and reads the
difficulty from **bytes [24..31]** of the 32-byte result as a little-endian
`uint64` — i.e. the most-significant 64-bit word, not the conventional final word.
The miner's `valid_hash` check mirrors this.

## Verification

Solutions are verified before submission (the solver's output is checked to collapse
to zero and to satisfy the ordering rules). A startup self-test can additionally
validate the Blake2b personalization, hash generation and index packing against known
`(header, solution)` vectors — important because the solver and verifier share code, so
a self-consistent encoding bug would pass local verification yet be rejected by the
pool. End-to-end correctness is confirmed by pool-accepted shares.

## Possible optimizations (preview)

Equihash performance is dominated by the solver's memory behaviour:

- **Memory bandwidth & layout** — the collision rounds are bound by random-access
  bandwidth; bucket layout and cache-friendly partitioning are the main levers.
- **SIMD Blake2b** — widen the generator with multi-way Blake2b to fill the table
  faster.
- **Per-variant tuning** — solver table sizes and bucket counts scale with `(n, k)`;
  tuning them per variant (especially the high-memory 192/7) improves throughput.
- **Threaded solving** — parallelize a single solver instance across cores for the
  large variants, rather than only running independent per-thread instances.
