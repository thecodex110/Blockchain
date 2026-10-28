---
tags: [concept, worklet/1]
aliases: [Transaction, TxInput, TxOutput, Coinbase]
---
# Transactions

File: `models/transaction.py`. Model: [[UTXO Model]].

## Shapes
- **`TxOutput`** — `amount`, `recipient_address` (32 B).
- **`TxInput`** — points at an earlier output by `(prev_tx_id, output_index)`, carries the spender's **public key** and **signature**.
- **`Transaction`** — `tx_type` (`COINBASE` or `TRANSFER`), inputs, outputs, `timestamp`.

## Rules
- **Transfer**: Σ inputs ≥ Σ outputs; difference = **fee** (goes to miner). Wallet adds a **change** output back to the sender.
- Each input's `SHA-256(pubkey)` must equal the owner of the output it spends, and its signature must verify.
- **Coinbase**: no inputs, always tx 0 of a block, pays `block_reward + fees`. Its `timestamp` field stores the **block height**, so every coinbase has a unique `tx_id` (fix D3).
- `tx_id = SHA-256(full tx bytes)`.
- **Signing preimage** = transaction serialized *without signatures* (`signing_preimage_bytes`), so the signature can't sign itself.

## Checks in this file
- `verify_signatures(...)`
- `validate_transaction_integrity(...)`
- `validate_block_transactions_no_double_spend(...)` — intra-block double spend & 1-byte tamper detection (REQ-005)

Flow: [[Life of a Transaction]]. Waiting room: [[Mempool]]. Inclusion: [[Merkle Tree]].
