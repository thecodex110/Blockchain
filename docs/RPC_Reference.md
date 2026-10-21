# RPC API Reference

Source of truth: `LedgerServerDispatcher._dispatch` in `blockchain_lite/network/server.py`.

## 1. TCP JSON-RPC (`TCPSocketLedgerServer`)

**Framing:** `[length: uint32 big-endian][UTF-8 JSON]`, at most 16 MiB per frame, loopback by default.
**Request:** `{"method": "<name>", "params": {...}}`.
**Response:** `{"ok": true, "result": {...}}` or `{"ok": false, "error": {"type": "<ErrorType>", "message": "<reason>"}}`.

**Server options:** `TCPSocketLedgerServer(ledger, host="127.0.0.1", port=0, client_timeout=5.0, max_workers=32, mine_token=None, allow_client_timestamp=False)`.

| Method | Params | Result | Notes |
| :--- | :--- | :--- | :--- |
| `get_chain_info` | `full` (bool, optional) | `height`, `tip_hash_hex`, `genesis_hash_hex`, `difficulty`, `block_reward`, `mempool_size`, `total_supply`, `is_valid` | `is_valid` is cached per tip; `full: true` forces an O(n) re-validation. `difficulty` is the protocol base difficulty. |
| `get_balance` | `address_hex` (64 hex) | `address_hex`, `balance` | Sum of the address's UTXOs. |
| `get_utxos` | `address_hex` | `address_hex`, `utxos[]` (`tx_id`, `output_index`, `amount`, `recipient_address`, `block_index`, `is_coinbase`) | |
| `submit_transaction` | `tx_bytes_hex` (canonical tx, ≤ 2 MiB) | `tx_id_hex`, `mempool_size` | Signed client-side. Rejects coinbases, timestamps > 2 h ahead, mempool/chain double-spends, fees below `min_fee`, a full mempool. Idempotent for duplicates. |
| `mine_block` | `auth_token` (required), `miner_address_hex` (optional), `timestamp` (only if `allow_client_timestamp`) | `block_index`, `block_hash_hex`, `previous_hash_hex`, `merkle_root_hex`, `nonce`, `difficulty`, `tx_count`, `hashes_tried`, `elapsed_seconds`, `block_bytes_hex` | Disabled unless the server has a `mine_token`. Refused if the next scheduled difficulty exceeds 20. |
| `get_block` | `block_index` | `block_index`, `block_hash_hex`, `previous_hash_hex`, `merkle_root_hex`, `timestamp`, `difficulty`, `nonce`, `tx_ids[]`, `block_bytes_hex` | |
| `get_headers` | `start_index` (≥ 0), `count` (1..2000) | `headers_hex[]` (88-byte headers) | Truncated at the tip. Used by `WalletClient.fetch_verified_headers`. |
| `get_merkle_proof` | `block_index`, `tx_id_hex` | `block_index`, `tx_id_hex`, `merkle_root_hex`, `proof_bytes_hex`, `step_count` | Verify against a header you trust, not against `merkle_root_hex`. |
| `get_transaction_history` | `address_hex` | `address_hex`, `history[]` | Entries: `block_index`, `tx_index`, `tx_id`, `tx_type`, `timestamp`, `is_sender`, `received_amount`, `total_output_amount`. |

**Error types:** `ValidationError` (bad/missing params, unknown method, policy refusals), `DoubleSpendError`,
`TamperDetectedError`, `SerializationError`, `BlockchainLiteError`, `SecurityViolationError`.

**Private keys:** no method accepts, needs, or returns one. As an extra tripwire, any param whose name
contains `private_key` is rejected with `SecurityViolationError`.

