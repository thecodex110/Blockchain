---
tags: [concept, worklet/shared]
---
# Canonical Serialization

**Why:** two machines must turn the same object into the *exact same bytes*, otherwise hashes and signatures disagree.

**How:** `ByteBuffer` (`blockchain_lite/serialization.py`) writes fields in a fixed order, **big-endian**, with explicit lengths:
- `uint8`, `uint32`, `uint64`
- `hash32` (exactly 32 bytes), `fixed_bytes(n)`
- `var_bytes` (length-prefixed, read cap 10 MiB), `utf8` (cap 1 MiB)
- `bigint` (for RSA numbers, cap 4096 bytes)

Reading must consume every byte — `assert_exhausted()` raises on leftover bytes, so trailing garbage can't hide in a valid-looking object.

Used by: [[Transactions]] (`to_bytes`, `signing_preimage_bytes`), [[Block and Header]] (88-byte header), [[Number Theory and RSA]] (key bytes), [[Persistence]] (`.bclt`), [[Merkle Tree]] (proof bytes).

Tests: `test_phase1_foundation`, `test_phase12_serialization_properties` (random round-trips + mutation). See [[Test Suite]].
