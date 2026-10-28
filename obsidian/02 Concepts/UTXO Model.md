---
tags: [concept, worklet/3]
aliases: [UTXO, UTXOSet]
---
# UTXO Model

Coins are not stored as "Alice: 500". Every transaction creates **outputs**; an output not yet spent is a **UTXO**. **Balance = sum of UTXOs owned by an address.** (Bitcoin-style.)

## `UTXOSet` — `ledger/utxo.py`
- Dict: `(tx_id, output_index) → UTXOEntry(amount, owner, block_index, is_coinbase)` → O(1) lookups.
- `apply_transaction` / `apply_block` work on a **clone**; the clone replaces the real set only if *every* transaction is valid → a bad block never leaves the set half-updated.
- `apply_block` enforces the **coinbase cap**: coinbase ≤ reward + fees.
- Queries: `compute_balance`, `get_utxos_for_address`, `get_spendable_utxos`, `total_supply`.

Related: [[Transactions]], [[Mempool]], [[Chain Validation]] (rebuilds the set from Genesis), [[Attack Defenses]].
