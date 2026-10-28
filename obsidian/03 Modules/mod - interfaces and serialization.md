---
tags: [module, worklet/shared]
files: [blockchain_lite/interfaces.py, blockchain_lite/serialization.py]
---
# mod — interfaces & serialization

## `interfaces.py` (shared foundation)
- **Exceptions**: `BlockchainLiteError` → `SerializationError`, `CryptoError`, `ValidationError` → `DoubleSpendError`, `TamperDetectedError`. (Network adds `NetworkRPCError`; server returns `SecurityViolationError` as an error *type*.)
- **Data**: `AvalancheReport`, `MerkleProofStep`, `MerkleProof`.
- **ABCs** (cross-worklet contracts):
  - `CanonicalSerializable` — `to_bytes` / `from_bytes`
  - `HashInterface` — `digest_size`, `hash_bytes`, `hash_hex`, `analyze_avalanche`
  - `AsymmetricCryptoInterface` — `generate_keypair`, `sign`, `verify`
  - `LedgerQueryInterface` — `get_balance`, `get_utxos_for_address`, `submit_transaction`, `get_merkle_proof`
- Constants (tx types, min RSA bits, size caps…).

## `serialization.py`
`ByteBuffer` — see [[Canonical Serialization]].

Back to [[Code Map]].
