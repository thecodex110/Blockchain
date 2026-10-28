---
tags: [module, worklet/3]
files: [blockchain_lite/ledger/chain.py, blockchain_lite/ledger/consensus.py, blockchain_lite/ledger/utxo.py, blockchain_lite/ledger/validator.py, blockchain_lite/ledger/pow.py, blockchain_lite/ledger/merkle.py, blockchain_lite/ledger/persistence.py]
---
# mod — ledger

The heart of the system. Each file has its own concept note:

| File | Concept |
|---|---|
| `merkle.py` | [[Merkle Tree]] |
| `pow.py` | [[Proof-of-Work]] |
| `consensus.py` | [[Difficulty Retargeting]] |
| `utxo.py` | [[UTXO Model]] |
| `validator.py` | [[Chain Validation]], [[Tamper Cascade]] |
| `persistence.py` | [[Persistence]] |
| `chain.py` | below |

## `BlockchainLedger` (`chain.py`, 748 lines)
Constructor defaults: `difficulty=8`, `block_reward=50`, `retarget_interval=0`, `target_block_time_seconds=10`, `min/max_difficulty=1/24`, `max_mempool_size=5000`, `min_fee=0`.

State: `_blocks`, `_utxo_set`, `_mempool` (tx_id → tx, insertion-ordered), `_mempool_spent` (claimed outpoints), `_address_history_index` (**O(1) address history**, ADV-003), `_health_cache` (validation report per tip).

Locks: `_lock` (`RLock`, state) and `_mining_lock` (one miner at a time; never blocks readers).

Main methods:
- Genesis: `create_genesis_block`, `load_verified_chain`
- Queries: `blocks`, `get_block`, `height`, `tip`, `genesis_hash`, `difficulty`, `mempool`, `total_supply`, `get_balance`, `get_spendable_utxos`, `get_utxos_for_address`, `get_merkle_proof`, `get_transaction_history`
- Consensus: `params`, `calculate_next_difficulty` (pure query), `enable/disable_dynamic_retargeting`, `add_checkpoint`
- Write: `submit_transaction(_object)` → [[Mempool]]; `mine_pending_transactions` + `append_mined_block` → [[Life of a Block]]; `resolve_forks` → [[Fork Resolution]]
- Checks: `validate_full_chain(force)`, `trace_tamper_cascade`

Back to [[Code Map]].
