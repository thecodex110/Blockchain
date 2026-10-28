---
tags: [concept, worklet/3]
---
# Mempool

The waiting room for valid transactions not in a block yet. Lives in `BlockchainLedger` (`ledger/chain.py`, `submit_transaction_object`).

Checks on submit:
- not a coinbase; timestamp ≤ now + 2 h
- inputs exist in the confirmed [[UTXO Model|UTXO set]] **and** aren't already claimed by another pending tx (`_mempool_spent`) → no double spend inside the mempool
- owner hash + signature valid, value conserved, fee ≥ `min_fee`
- duplicates are idempotent; size cap `max_mempool_size` (5000)

Validation is **incremental** (one signature check per submission, fix D9). Mined in [[Life of a Block]].
