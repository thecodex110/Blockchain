---
tags: [concept, worklet/3]
aliases: [FullChainValidator, Validation]
---
# Chain Validation

File: `ledger/validator.py`. Anyone can check a whole chain without trusting the sender.

`FullChainValidator` walks Genesis → tip and, per block, checks:
1. index order & `previous_hash` link
2. header hash & `verify_crystallized_integrity` (Merkle root recomputed)
3. [[Proof-of-Work]] meets the declared difficulty
4. declared difficulty == schedule ([[Difficulty Retargeting]]); timestamps; coinbase height
5. every signature & ownership check ([[Transactions]])
6. no double spends; coinbase ≤ reward + fees — while rebuilding the [[UTXO Model|UTXO set]]
7. optional **pinned Genesis** (trust anchor) and **checkpoints** (`register_checkpoint`)

API: `validate_chain_or_raise`, `validate_chain` → `ChainValidationReport` (one-pass `failed_block_index`), `trace_tamper_cascade` → `TamperCascadeReport` ([[Tamper Cascade]]).

`BlockchainLedger.validate_full_chain(force=False)` caches the report per tip (fix D7).
