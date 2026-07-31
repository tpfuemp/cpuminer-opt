# VerusHash 2.2

**Coin:** Verus Coin (VRSC)
**Algorithm name:** `verus`
**Family:** Haraka512 Merkle–Damgård chain + a self-modifying carryless-multiply hash

```
./cpuminer -a verus -o stratum+tcp://<pool>:<port> -u <wallet>.<worker> -p x
```

---

## Overview

VerusHash 2.2 is deliberately hostile to fixed-function hardware. It has two stages:

1. **`VerusHashHalf`** — the 1472 job-constant bytes of the 1487-byte preimage are
   absorbed by a Haraka512 Merkle–Damgård chain. This depends only on the job, so it
   runs once per job, not once per nonce.
2. **`verusclhashv2_2`** — 32 rounds over a 8832-byte key derived from the half-state,
   each round selected by the accumulator itself (an AES round, a carryless multiply,
   a 64-bit modulo, or a variable-length inner loop). Rounds **mutate the key as they
   read it**, and a journal of up to 64 changed slots is replayed to restore it after
   every nonce. The final Haraka512 compression takes its round constants from the
   mutated key at a data-dependent offset.

The last stage is truncated to bytes 28..31 of the digest, which is the whole target
test; a candidate is then re-hashed in full so the submitted digest is complete.

The wire format is Equihash 200/9's — 140-byte header, 32-byte nonce field, 1344-byte
solution — and is shared with it in the code. **PBaaS headers submit a zeroed `nNonce`**,
with the real nonce living in the last 15 bytes of the solution; pools reject anything
else.

## Instruction requirements

The inner loop is built from three primitives: an AES round, a 64×64→128 carryless
multiply, and `_mm_mulhrs_epi16`.

| Target | AES round | Carryless multiply |
|---|---|---|
| x86-64 | AES-NI (`-maes`) | PCLMULQDQ (`-mpclmul`) |
| aarch64 with the ARMv8 crypto extension | `AESE`+`AESMC` | `PMULL64` |
| aarch64 without it | emulated in NEON | emulated in NEON |

x86-64 without AES-NI and PCLMULQDQ refuses to register the algorithm. **aarch64
always works**: cores without the crypto extension (Cortex-A53 / A72 — Raspberry Pi 3
and Pi 4, RK3328, Allwinner H5/H6) get bit-exact emulations from
`simd-utils/simd-neon-aes.h` and `simd-utils/simd-neon-clmul.h` instead of having
VerusHash compiled out.

### The emulated fallback, and what it costs

Measured on an RK3588S, both builds pinned to one core at a fixed clock, hashing the
same preimage (digests verified identical):

| core | hardware | emulated | |
|---|---|---|---|
| Cortex-A55 @ 1.8 GHz (in-order, like an A53) | 433 kH/s | **130 kH/s** | 3.3× slower |
| Cortex-A76 @ 2.3 GHz (out-of-order) | 923 kH/s | **333 kH/s** | 2.8× slower |

- **Expect roughly a third of the hashrate** of the same core with the extension — better
  than the order of magnitude the instruction counts suggest, because a hash is more than
  its AES rounds. Per primitive the gap is larger: an AES round costs 27.5 ns emulated
  against 4.4 ns hardware, a carryless multiply 39.7 ns against 5.0 ns. A Pi 3
  (A53 @ 1.2 GHz) should land near 85 kH/s per core, so ~250–350 kH/s for four — a
  projection from the A55 figure, not a measurement.
- The S-box is the tower-field (GF(2^4)²) construction: nibble lookups only, so it holds
  10 constant registers instead of the 256-entry table's 16. That is worth **+30% per hash
  on the A55** even though it makes the isolated AES round *slower* — on these cores the
  emulation is bound by register pressure, not by lookup count.
- The miner logs a warning at startup saying which primitive is emulated.
- **If the CPU does have the extension, this is a misconfiguration.** A Pi 4 built
  with `-march=armv8-a` will emulate; build with `-march=armv8-a+crypto` (Pi 4,
  RK3399) or `-march=armv8.2-a+crypto` (A76-class: RK3588, Orange Pi 5) instead.
  `armbuild-all.sh` builds both variants.
- **A 64-bit OS is required.** The NEON layer is `__aarch64__`-only, so 32-bit
  Raspbian / armhf is not supported even on hardware that could run it.
- On a 1 GB Pi 3 the per-thread context is ~10 KB but the 8832-byte key is re-read
  randomly every round, so four threads will be memory-bound before they are AES-bound.
- The emulation is still far ahead of the alternative: routing everything through the
  scalar software-AES path instead would cost 96.5 ns per AES round and 202 ns per
  carryless multiply, i.e. ~4–5× worse than the NEON emulation on the same core.

## Verification

The startup self-test is a **real-block known-answer test**: `algo/verus/verus-kat.h`
holds mainnet block 4174000 exactly as the chain serializes it, and the test reproduces
its published hash. For a PBaaS header the published block hash *is* the canonical PoW
hash, so one block pins the whole chain, the canonical field clearing, and the 15-byte
nonce placement at once. Two free invariants are asserted alongside it: that the
truncated Haraka writes only bytes 28..31, and that the journal restores the key to
pristine after every hash.

On a build using the emulated primitives, the self-test first checks each primitive
against an independent scalar reference (the table-driven `aesenc()` in
`haraka_portable.c`, and a bit-loop carryless multiply) over ~4100 vectors plus the
all-zero / all-ones / `0x80` edge cases, so an emulation bug is reported as an
emulation bug rather than as a digest mismatch. **The miner refuses to mine if any of
this fails.**

Pool-accepted shares confirm x86-64 and aarch64 with hardware AES.
