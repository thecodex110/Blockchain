---
tags: [concept, worklet/2]
aliases: [Block, BlockHeader, Header]
---
# Block and Header

File: `models/block.py`. A block = header + list of [[Transactions]].

## The 88-byte header
| Field | Size | Meaning |
|---|---:|---|
| `index` | 4 B | height (Genesis = 0) |
| `previous_hash` | 32 B | hash of the previous block — **the chain** |
| `merkle_root` | 32 B | commits to all txs ([[Merkle Tree]]) |
| `timestamp` | 8 B | Unix seconds |
| `difficulty` | 4 B | required leading zero bits ([[Proof-of-Work]]) |
| `nonce` | 8 B | what the miner varies |

**Block hash = SHA-256(header)**. Only the header is hashed, but because it holds the Merkle root, the hash still depends on every transaction.

## Code
- `BlockHeader.to_bytes / from_bytes / compute_hash` (used standalone for SPV)
- `Block.header_bytes(nonce_override)`, `pack_header_prefix` (fast nonce loop)
- `compute_merkle_tree`, `compute_merkle_root`, `generate_merkle_proof`
- `verify_crystallized_integrity` — stored Merkle root & hash match the content

Why `previous_hash` makes the chain tamper-evident → [[Tamper Cascade]].
