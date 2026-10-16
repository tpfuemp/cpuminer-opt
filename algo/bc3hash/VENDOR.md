# bc3hash: provenance

Source: Bitcoin III Core, <https://gitlab.com/bitcoiniii/bitcoiniii-core>,
commit `ac3dbe8b47c6b822531ed7f7dfc2fa4e9a295b2a` (2026-10-14), `src/crypto/bc3/`.
MIT license, same as the rest of that repository.

## File mapping

| Here | Upstream | Relation |
|---|---|---|
| `bc3hash-uint.hpp` | `uint.hpp` | Same arithmetic. `constexpr` dropped in places; the 512-bit moduli (`M512`, `F512`) removed |
| `bc3hash-constants.hpp` | `constants.hpp` | Same values, same order. `E512`, `g512`, `BC3FOLD_CONST` removed |
| `bc3hash-core.cpp` | `mix.cpp` + `hash.cpp` | Derived; see below |
| `bc3hash-hashes.hpp` | `standard_hashes.hpp` | Same interface |
| `bc3hash-hashes-framework.cpp` | `standard_hashes.cpp` | Rewritten on this tree's `sph_*` hashes |

## What was removed

- **BC3Fold** (`Fold`, `bc3fold`, `generator_table`, the streaming `Mix`/`Hash` classes):
  BC3Mix only folds inputs that are not exactly 64 bytes. bc3hash always feeds it the
  64-byte SHA3-512 digest, so the fold never runs on the PoW path.
- `configure()` / `Mode`: replaced by the runtime window below.

## What was changed

- The curve table window is set at runtime (`-a bc3hash:W`, default 16) instead of
  through upstream's compact/fast mode (windows 10/16). Digests are identical at every window.
- The secp256k1 context and the tables are allocated once and never freed. The miner
  calls `exit()` while hashing threads are still running, and destroying them then
  is a use-after-free.
- The 64-bit message schedule in `mix512` runs over a rolling window instead of
  indexing the array it writes. Upstream's form is miscompiled by gcc 13 at `-O3`
  unless `-fno-strict-aliasing` is set (the loop vectorizer breaks its distance-1
  recurrence). Same values, checked against the coin's reference.
- `CurveTable` caches the context pointer. `inverse_odd64(36113)` is folded to a constant.
- The structured bindings in `mix512` are spelled out as `std::pair` members.
- An `extern "C"` API (`bc3_hash_cxx`, `bc3_hash_init_cxx`, `bc3_hash_*_window`,
  `bc3_hash_table_bytes`) for the C gate.

The elliptic-curve operations use the libsecp256k1 already vendored for curvehash,
through its public API only.

## Checking a re-sync

Don't compare by eye. Parse both sides:

- every `::hex("...")` constant in `bc3hash-constants.hpp` must appear in upstream's
  `constants.hpp`, in the same order;
- `mix512`, `inverse256` and its helpers in `bc3hash-core.cpp` must match `mix.cpp`
  after whitespace normalisation, except for the changes listed above;
- the functions in `bc3hash-uint.hpp` must match `uint.hpp` modulo `constexpr`/`inline`.

Then the startup self-test (`bc3hash-kat.h`, two mainnet blocks and two of upstream's
`doc/bc3/vectors/header-vectors.json` entries) must pass at windows 10 and 16.
