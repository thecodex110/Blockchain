---
tags: [project, requirements]
---
# Requirements Matrix

All marked **SATISFIED** in the README.

| ID | Requirement | Main code | Note |
|---|---|---|---|
| REQ-001 | Modular arithmetic, fast modexp O(log e) | `number_theory.py` | [[Number Theory and RSA]] |
| REQ-002 | Miller–Rabin, large primes, keypairs | `number_theory.py`, `asymmetric.py` | |
| REQ-003 | `Transaction` (`TxInput`, `TxOutput`) & `Wallet` | `transaction.py`, `wallet.py` | [[Transactions]] |
| REQ-004 | sign/verify, canonical serialization | `serialization.py`, `asymmetric.py` | [[Canonical Serialization]] |
| REQ-005 | detect double spend & 1-byte tamper in a block | `transaction.py`, `utxo.py` | |
| REQ-006 | `Block` & predecessor-hash chaining | `block.py` | [[Block and Header]] |
| REQ-007 | binary Merkle tree | `merkle.py` | [[Merkle Tree]] |
| REQ-008 | O(log N) inclusion proofs | `merkle.py`, `client.py` | [[SPV Light Client]] |
| REQ-009 | bit-level hash + avalanche | `hashing.py` | [[SHA-256]] |
| REQ-010 | PoW with adjustable, enforced difficulty | `pow.py`, `consensus.py` | [[Proof-of-Work]] |
| REQ-011 | Genesis validation & most-work forks | `validator.py`, `chain.py` | [[Fork Resolution]] |
| REQ-012 | UTXO scanning, query interface, persistence | `utxo.py`, `persistence.py`, `server.py` | [[Persistence]] |
| REQ-013 | PoW difficulty vs time measurement | `pow_benchmark.py` | [[mod - benchmarks]] |
| ARC-001 | wallet client ↔ ledger server over TCP | `network/` | [[mod - network]] |
| ADV-001 | bounded thread-pool server, reads not blocked by mining | `server.py`, `chain.py` | |
| ADV-002 | dynamic retargeting, enforced | `consensus.py` | [[Difficulty Retargeting]] |
| ADV-003 | O(1) address history | `chain.py` | [[mod - ledger]] |
| ADV-004 | checkpoints & pinned Genesis | `validator.py` | [[Chain Validation]] |
| ADV-005 | interactive terminal console | `terminal.py` | [[mod - cli]] |
| CON-001 | stdlib only (except opt-in `fast_hash.py`) | all | [[Test Suite]] |
