---
tags: [module]
files: [blockchain_lite/models/transaction.py, blockchain_lite/models/block.py]
---
# mod — models

- `transaction.py` — `TxInput`, `TxOutput`, `Transaction` (`create_coinbase`, `signing_preimage_bytes`, `tx_id`, `verify_signatures`), `validate_transaction_integrity`, `validate_block_transactions_no_double_spend` → [[Transactions]]
- `block.py` — `BlockHeader` (88 B), `Block` (`header_bytes`, `compute_header_hash`, `compute_merkle_tree`, `generate_merkle_proof`, `verify_crystallized_integrity`) → [[Block and Header]]

Back to [[Code Map]].
