# SkyDoge

**Coin:** SkyDoge
**Algorithm name:** `skydoge`
**Family:** fixed-order chained hash (an X-family extension)

```
./cpuminer -a skydoge -o stratum+tcp://<pool>:<port> -u <wallet> -p x
```

---

## Overview

SkyDoge runs a fixed sequence of 20 well-known hashes, each consuming the previous
one's output. Like the [X-chains](x-chains.md), the order is fixed (it does not depend
on the header), so there is no branching and no memory-hard step — it is compute-bound
and parallelizes cleanly. It uses the standard Bitcoin-style Stratum flow (80-byte
header, 32-bit nonce, sha256d merkle root).

The 32-byte result of the final hash is the proof-of-work hash compared against the
target.

## Structure

20 stages. The first consumes the 80-byte header; every later stage consumes the
previous 64-byte output:

```
 1 blake512     2 skein512     3 bmw512      4 groestl512   5 jh512
 6 luffa512     7 keccak512    8 simd512      9 echo512     10 cubehash512
11 shavite512  12 hamsi512    13 fugue512    14 shabal512   15 whirlpool
16 sha512      17 simd512     18 whirlpool   19 sha256      20 haval256-5
```

Notes:
- `simd512` and `whirlpool` each run **twice** (stages 8 & 17, and 15 & 18).
- **Finalization:** stage 19 (`sha256`) writes a 32-byte digest into the low half of a
  64-byte buffer; the high 32 bytes are zeroed; stage 20 (`haval256-5`) then hashes the
  full 64-byte buffer. The first 32 bytes of its output are the result.

## Performance

Because the chain is fixed and nonce-independent, SkyDoge is compute-bound and benefits
directly from the project's optimized single-hash cores:

- **Hardware AES** (AES-NI / ARMv8 crypto) for the AES-based rounds — Groestl, Echo,
  Fugue.
- **SSE2 / vector** implementations for Luffa, CubeHash and SIMD, plus the optimized
  Blake-512 core.
- Every optimized core is bit-identical to the scalar reference (verified by the
  startup KAT below).

## Verification

A known-answer test runs at startup against a known `(header → hash)` vector and
**refuses to mine on mismatch**, so a miscompiled or divergent build can never submit
invalid shares. End-to-end correctness is confirmed by pool-accepted shares.

## Possible optimizations (preview)

- **Parallel-lane hashing** — batch several nonces per pass with 4/8/16-way (AVX2 /
  AVX-512) implementations, as the X-chains do. The fixed, nonce-independent order
  makes this the largest remaining throughput gain.
- **Wider AES** — VAES for the AES-based rounds on supporting CPUs.
