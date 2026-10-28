---
tags: [concept, network]
aliases: [SPV]
---
# SPV Light Client

**Simplified Payment Verification**: prove a tx is in a block using only headers + a [[Merkle Tree|Merkle proof]] — no full block download.

In `network/client.py` (`WalletClient`):
1. `fetch_verified_headers` — downloads 88-byte headers via RPC `get_headers` (≤ 2000 per call), checks links, PoW and the difficulty schedule starting from a **trusted Genesis hash**.
2. `verify_transaction_inclusion_spv(..., trusted_genesis_hash=, params=)` — gets the proof via `get_merkle_proof` and verifies it against the **header root it verified itself**, not the server's `merkle_root_hex`.

Tests: `test_phase13_spv_and_keys`. Related: [[Block and Header]], [[mod - network]].
