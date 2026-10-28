---
tags: [module, network]
files: [blockchain_lite/network/transport.py, blockchain_lite/network/server.py, blockchain_lite/network/client.py]
---
# mod — network

## Transport (`transport.py`)
Frame = `[uint32 big-endian length][UTF-8 JSON]`, max **16 MiB**. `send_framed_json`, `recv_exact`, `recv_framed_json`, `ClientTransport` ABC, `NetworkRPCError`.

## Server (`server.py`)
- `LedgerServerDispatcher.handle_request` → `{"ok": true, "result": …}` or `{"ok": false, "error": {type, message}}`.
- **Tripwire**: any param name containing `private_key` → `SecurityViolationError`.
- `TCPSocketLedgerServer(ledger, host="127.0.0.1", port=0, client_timeout=5.0, max_workers=32, mine_token=None, allow_client_timestamp=False)` — bounded `ThreadPoolExecutor`, loopback default (ADV-001).
- `InMemoryTransport` for tests.

## RPC methods
| Method | Purpose |
|---|---|
| `get_chain_info` | height, tip/genesis hash, difficulty, reward, mempool size, supply, `is_valid` (cached; `full: true` re-validates) |
| `get_balance`, `get_utxos` | by `address_hex` |
| `submit_transaction` | `tx_bytes_hex` (≤ 2 MiB), signed client-side |
| `mine_block` | needs `auth_token` == server `mine_token`; refused if next D > 20 |
| `get_block` | header fields + tx ids + raw bytes |
| `get_headers` | `start_index`, `count` 1..2000 → 88-byte headers (SPV) |
| `get_merkle_proof` | `block_index`, `tx_id_hex` |
| `get_transaction_history` | per address |

## Client (`client.py`)
`WalletClient(wallet, transport)`: `get_chain_info`, `get_balance`, `get_spendable_utxos`, `send_funds` (signs locally), `request_mining`, `fetch_verified_headers`, `verify_transaction_inclusion_spv`, `get_transaction_history`. → [[SPV Light Client]]

Full reference: `docs/RPC_Reference.md`. Back to [[Code Map]].
