# Blockchain-Lite Ledger & Digital Wallet

**COEP Technological University · Department of Computer Science and Engineering**  
*A Foundations-First Framework Implementation (Python 3.11+ Standard Library Only)*

> **Educational software — not for real assets.** Demo keys are 384-bit RSA, the signature scheme is
> custom and not constant-time. See [`SECURITY.md`](SECURITY.md) for the threat model and known limitations.

---

## 1. Project Overview

This repository implements an educational, tamper-evident, UTXO-based **Blockchain-Lite Ledger & Digital Wallet** built from mathematical and algorithmic first principles: big-integer modular arithmetic, Miller–Rabin primality testing, RSA signatures, bit-level SHA-256, binary Merkle trees with $O(\log_2 N)$ inclusion proofs, adjustable-difficulty Proof-of-Work with an **enforced difficulty schedule** (optional retargeting), Genesis-to-tip chain validation, **most-cumulative-work** fork resolution, $O(1)$ address history indexing, a client–server TCP RPC layer, anchored SPV light-client verification, an interactive terminal console, and tamper-evident binary persistence. Everything is built without external cryptography libraries, blockchain SDKs, databases/ORMs, or web frameworks.

Standard-library-only compliance is enforced by an AST import audit (`TestExclusionsCompliance`) over every package module. The single documented exception is the **opt-in** `crypto/fast_hash.py`, which wraps `hashlib` for a faster, bit-identical SHA-256 backend.

---

## 2. Repository Structure & Worklet Mapping

| Module Path | Worklet / Layer | Responsibilities |
| :--- | :--- | :--- |
| `blockchain_lite/interfaces.py` | Shared Foundation | Cross-worklet abstract interfaces (`CanonicalSerializable`, `HashInterface`, `AsymmetricCryptoInterface`, `LedgerQueryInterface`), constants, and exceptions |
| `blockchain_lite/serialization.py` | Shared Foundation | Deterministic big-endian `ByteBuffer` binary serializer and deserializer |
| `blockchain_lite/crypto/hashing.py` | Worklet 2 (DLCO) | From-scratch 32-bit bitwise FIPS 180-4 SHA-256 engine (`BitLevelSHA256`, the default), round-state tracer, and avalanche analyzer |
| `blockchain_lite/crypto/fast_hash.py` | Optional backend | `HashlibSHA256`: opt-in (`--fast-hash`), bit-identical, ~650x faster hashing; the only module allowed to import `hashlib` |
| `blockchain_lite/crypto/number_theory.py` | Worklet 1 (Discrete) | `mod_add`, `mod_sub`, `mod_mul`, $O(\log e)$ `pow_mod` with op-count trace, Extended GCD, `mod_inverse`, 40-round Miller–Rabin primality, and large prime generator |
| `blockchain_lite/crypto/asymmetric.py` | Worklet 1 (Discrete + OOP) | `RSAPublicKey`, `RSAPrivateKey`, and `RSACryptoEngine` (keypair generation, domain-separated deterministic signing, verification, key-size warnings) |
| `blockchain_lite/models/transaction.py` | Worklet 1 (OOP) | `TxInput`, `TxOutput`, `Transaction` (`COINBASE` & `TRANSFER`), canonical signing preimage, and intra-block double-spend & tamper detection |
| `blockchain_lite/wallet/wallet.py` | Worklet 1 (Client) | `Wallet` class isolating private keys on the client, deterministic UTXO coin selection, change calculation, and transaction signing |
| `blockchain_lite/ledger/merkle.py` | Worklet 2 (DSA) | Domain-separated binary `MerkleTree` (`0x00` leaf / `0x01` internal node prefixes) and $O(\log_2 N)$ `MerkleProof` generation & verification with odd-tail spoofing guard |
| `blockchain_lite/models/block.py` | Worklet 2 (DSA) | `Block` and 88-byte `BlockHeader` models, predecessor hash chaining (`previous_hash`), and crystallized Merkle/header verification |
| `blockchain_lite/ledger/pow.py` | Worklet 2 (DSA + DLCO) | `ProofOfWorkMiner` nonce search and verification by leading-zero-bit difficulty $D \in [0, 256]$ |
| `blockchain_lite/ledger/consensus.py` | Worklet 3 | Single source of truth for consensus rules: `ConsensusParams`, `expected_difficulty` (fixed or retargeted, derived from history), timestamp bounds, coinbase height commitment |
| `blockchain_lite/ledger/utxo.py` | Worklet 3 (DSA) | Hash-map backed `UTXOSet` (`(tx_id, output_index) -> UTXOEntry`), atomic staged updates, coinbase cap enforcement, and balance/UTXO scanning |
| `blockchain_lite/ledger/validator.py` | Worklet 3 | `FullChainValidator` (Genesis-to-tip verification incl. consensus rules, pinned Genesis trust anchor, checkpoints, one-pass failing index) |
| `blockchain_lite/ledger/chain.py` | Worklet 3 | Thread-safe `BlockchainLedger`: most-work fork resolution, cached chain health, incremental mempool with caps, mining outside the state lock, $O(1)$ address history |
| `blockchain_lite/ledger/persistence.py` | Worklet 3 | `ChainPersistence` (`BCLT` binary format, atomic `.tmp` + `fsync` + `os.replace` write, SHA-256 envelope seal, re-validation under caller-supplied protocol parameters) |
| `blockchain_lite/benchmarks/pow_benchmark.py` | Worklet 3 | PoW difficulty vs. mining time profiler (mean, median, stdev, min, max, Geometric-distribution analysis) and hash-backend throughput comparison |
| `blockchain_lite/network/transport.py` | Integration (Network) | Wire framing (4-byte big-endian length prefix + JSON envelope, 16 MiB cap) |
| `blockchain_lite/network/server.py` | Integration (Server) | `TCPSocketLedgerServer` with bounded `ThreadPoolExecutor`, loopback default, per-client timeout, strict RPC dispatch, token-gated mining, `get_headers` for SPV |
| `blockchain_lite/network/client.py` | Integration (Client) | `WalletClient`: signs locally, never sends private keys; anchored SPV (`fetch_verified_headers`) |
| `blockchain_lite/cli/terminal.py` | Terminal Explorer | Interactive terminal console & explorer: blocks, mempool, wallet balances, RSA transfers, PoW mining, SPV Merkle proofs, tamper simulation |
| `blockchain_lite/cli/demo.py` | Integration & Viva | Self-contained 6-stage demonstration runner (`--rsa-bits` selectable) |
| `tests/` (12 modules) | Verification Suite | Worklet tests, end-to-end lifecycle, attack scenarios (D1–D8), serialization property/mutation tests, fast-hash equivalence, SPV, terminal console checks |
| `tools/bundle.py` | Monolithic Bundler | Generates the standalone `blockchain_lite_complete.py` |

**Start here:** [`docs/Project_Guide.md`](docs/Project_Guide.md) explains the whole project in plain language; [`docs/Frontend_Guide.md`](docs/Frontend_Guide.md) explains every page and button of the browser app.

Further documentation: [`docs/Protocol_and_Architecture_Specification.md`](docs/Protocol_and_Architecture_Specification.md) (wire formats and consensus rules), [`docs/HLD_and_Interfaces.md`](docs/HLD_and_Interfaces.md) (design and benchmarks), [`docs/RPC_Reference.md`](docs/RPC_Reference.md), [`docs/Viva_Guide_and_Design_Journal.md`](docs/Viva_Guide_and_Design_Journal.md), [`SECURITY.md`](SECURITY.md), [`CHANGELOG.md`](CHANGELOG.md).

---

## 3. Setup, Testing & Terminal Execution Instructions

```bash
# 1. Run the interactive terminal console:
python3 run_terminal.py

# 2. Run with fast hash backend:
python3 run_terminal.py --fast-hash

# 3. Run the automated 6-stage evaluation demo:
python3 run_terminal.py --demo

# 4. Check chain status directly:
python3 run_terminal.py --status

# 5. Run the full automated test suite:
python3 run_tests.py
```

### 3.1 Web Explorer & Live Visualization (`web/`, `viz/`)

A browser frontend (plain HTML/CSS/JS) on top of a standard-library HTTP bridge. Both live outside the `blockchain_lite` package, so the package stays standard-library only.

```bash
# Start the bridge and open http://127.0.0.1:8080
python3 -m web.bridge

# Optional: also render a Manim video of every newly mined block (pip install manim)
python3 -m web.bridge --render

# Render one block from a running bridge by hand
python3 -m viz.render --block 10

# Difficulty retargeting (on by default): target 10 s per block, checked every 4 blocks
python3 -m web.bridge --block-time 10 --retarget-interval 4 --auto-mine
python3 -m web.bridge --retarget-interval 0     # fixed difficulty, as before

# The welcome page asks for an 8-digit passcode (demo default 12345678)
python3 -m web.bridge --passcode 24681357
```

Difficulty follows the consensus rule in `ledger/consensus.py`: every `retarget_interval` blocks, if the recent blocks came faster than 0.75× the target it rises by one bit (twice the expected work), slower than 1.33× it drops by one bit. **Auto-mine** keeps a background miner running, so you can watch the difficulty climb until blocks take about the target time.

| Page | What it shows |
| :--- | :--- |
| **Explorer** | Chain strip linked by `previous_hash`, block inspector with the 88-byte header, Merkle tree with SPV proof paths, send-coins form, mempool, live SSE events |
| **Block Forge** | Five animated steps replayed from a real block: collect transactions → SHA-256 + avalanche → Merkle tree → nonce search → append to chain |
| **Tamper Lab** | Every person keeps a ledger copy; edit one copy, see the broken Merkle root and orphaned blocks, then watch the periodic network check restore it from the valid majority |
| **People** | Add a person (new RSA wallet + ledger copy), make transactions by hand, and press **Add block to blockchain** |

The bridge (`web/bridge.py`) reuses `LedgerServerDispatcher` for reads and transaction submission, streams `tx_submitted` / `block_mined` / `render_ready` over `/events`, binds to loopback by default, and uses the bit-identical hashlib SHA-256 for responsiveness (`--bit-level-hash` switches to the from-scratch engine). Like the terminal console, it holds the demo wallets and signs for them — a classroom convenience, not a real wallet design.

## 4. Standalone Monolithic Distribution (`blockchain_lite_complete.py`)

A single-file terminal build:

```bash
# 1. Launch the interactive terminal console:
python blockchain_lite_complete.py

# 2. Run the 6-stage demo:
python blockchain_lite_complete.py --demo

# 3. Run the full test-suite:
python blockchain_lite_complete.py --test

# 4. Unpack the modular project into a directory:
python blockchain_lite_complete.py --unpack ./blockchain_lite_project
```

To regenerate it from source:
```bash
python tools/bundle.py
```

---

## 5. Containerized Deployment (Docker & Compose)

The image runs as a non-root user and executes the full test-suite during the build.

```bash
# Interactive terminal console:
docker compose run --rm terminal

# 6-stage CLI demo:
docker compose --profile demo run --rm cli-demo

# Full automated test-suite:
docker compose --profile test run --rm test-suite
```

---

## 6. Requirements & Compliance Matrix

| Req ID | Official Guideline Requirement | Primary Implementation | Verification Suite | Status |
| :--- | :--- | :--- | :--- | :--- |
| **`REQ-001`** | Worklet 1.1: Modular arithmetic & fast modular exponentiation ($O(\log e)$) | `blockchain_lite/crypto/number_theory.py` | `test_phase2_worklet1.py`, `test_phase6_defensive_verification.py` | **SATISFIED** |
| **`REQ-002`** | Worklet 1.2: Miller–Rabin primality, large primes & public/private keypair generation | `number_theory.py`, `asymmetric.py` | `test_phase2_worklet1.py`, `test_phase13_spv_and_keys.py` (2048-bit) | **SATISFIED** |
| **`REQ-003`** | Worklet 1.3: `Transaction` (`TxInput`, `TxOutput`) & `Wallet` holding keypair | `transaction.py`, `wallet.py` | `test_phase2_worklet1.py`, `test_phase6_defensive_verification.py` | **SATISFIED** |
| **`REQ-004`** | Worklet 1.4: Sign transactions with private key, verify with public key, canonical serialization | `serialization.py`, `asymmetric.py`, `transaction.py` | `test_phase1_foundation.py`, `test_phase2_worklet1.py`, `test_phase12_serialization_properties.py` | **SATISFIED** |
| **`REQ-005`** | Worklet 1.5: Detect double-spending & 1-byte tampering within a block | `transaction.py`, `utxo.py` | `test_phase2_worklet1.py`, `test_phase12_serialization_properties.py` | **SATISFIED** |
| **`REQ-006`** | Worklet 2.1: `Block` (`transactions`, `previous_hash`, `nonce`) & predecessor-hash chaining | `blockchain_lite/models/block.py` | `test_phase3_worklet2.py`, `test_phase6_defensive_verification.py` | **SATISFIED** |
| **`REQ-007`** | Worklet 2.2: Binary Merkle tree over a block's transactions | `blockchain_lite/ledger/merkle.py` | `test_phase3_worklet2.py`, `test_phase9_core_engineering.py` (odd-tail duplication) | **SATISFIED** |
| **`REQ-008`** | Worklet 2.3: Produce and verify $O(\log_2 N)$ Merkle inclusion proofs | `merkle.py`, `client.py` (anchored SPV) | `test_phase3_worklet2.py`, `test_phase13_spv_and_keys.py` | **SATISFIED** |
| **`REQ-009`** | Worklet 2.4: Bit-level hash interface (`BitLevelSHA256`) & avalanche tamper-evidence | `blockchain_lite/crypto/hashing.py` | `test_phase1_foundation.py`, `test_phase11_fast_hash.py` | **SATISFIED** |
| **`REQ-010`** | Worklet 2.5: Proof-of-Work mining with adjustable difficulty ($D$ leading zero bits), enforced by schedule | `pow.py`, `consensus.py` | `test_phase3_worklet2.py`, `test_attack_scenarios.py` | **SATISFIED** |
| **`REQ-011`** | Worklet 3.1 & 3.2: Full-chain validation from Genesis & fork resolution (most cumulative valid work) | `validator.py`, `chain.py`, `consensus.py` | `test_phase4_worklet3.py`, `test_attack_scenarios.py` | **SATISFIED** |
| **`REQ-012`** | Worklet 3.3 & 3.4: UTXO balance scanning, ledger query interface & tamper-evident persistence | `utxo.py`, `persistence.py`, `server.py` | `test_phase4_worklet3.py`, `test_attack_scenarios.py` (D2) | **SATISFIED** |
| **`REQ-013`** | Worklet 3.5: Empirical measurement of PoW difficulty vs. mining time | `blockchain_lite/benchmarks/pow_benchmark.py` | `test_phase4_worklet3.py`, `test_phase11_fast_hash.py` | **SATISFIED** |
| **`ARC-001`** | Client-server separation (Wallet client isolated from Ledger server over TCP RPC) | `blockchain_lite/network/` | `test_phase5_integration.py`, `test_phase9_core_engineering.py` | **SATISFIED** |
| **`ADV-001`** | Bounded thread-pool RPC server; reads not blocked by mining | `server.py`, `chain.py` | `test_phase7_advanced_features.py`, `test_phase9_core_engineering.py` | **SATISFIED** |
| **`ADV-002`** | Dynamic difficulty retargeting (deterministic, enforced on validation) | `consensus.py`, `chain.py` | `test_phase7_advanced_features.py`, `test_attack_scenarios.py` | **SATISFIED** |
| **`ADV-003`** | $O(1)$ address history indexing | `chain.py` | `test_phase7_advanced_features.py` | **SATISFIED** |
| **`ADV-004`** | Checkpoints and pinned Genesis trust anchor | `validator.py`, `chain.py`, `persistence.py` | `test_phase7_advanced_features.py`, `test_phase4_worklet3.py` | **SATISFIED** |
| **`ADV-005`** | Interactive terminal console & explorer (stateful, accessible, zero-dependency) | `blockchain_lite/cli/terminal.py` | `test_terminal_console.py` | **SATISFIED** |
| **`CON-001`** | Pure Python 3.11+ standard library only (one documented opt-in exception: `fast_hash.py` → `hashlib`) | All modules in `blockchain_lite/` | `TestExclusionsCompliance` in `test_phase1_foundation.py` | **SATISFIED** |

---

## 7. Final Live Demonstration Plan (6 Stages)

Executing `python -m blockchain_lite.cli.demo` runs the deterministic 6-stage evaluation sequence:
1. **Stage 1 (Worklet 1 — Number Theory & RSA):** Traces binary square-and-multiply (`272` modular ops for a 256-bit exponent), verifies rejection of Carmichael numbers (`561, 1105, 1729, 2465, 6601`), and generates isolated client wallets.
2. **Stage 2 (Client-Server TCP Workflow & Worklet 3.3):** Starts `TCPSocketLedgerServer` on `127.0.0.1` (mining enabled with a demo token), queries UTXO balances via `WalletClient`, submits signed transfers over TCP sockets, mines Block `#1`, and reconciles post-block balances.
3. **Stage 3 (Worklet 2 — Bit-Level Avalanche & SPV Merkle Proof):** Demonstrates ~50% bit-flip avalanche on a 1-bit transaction change and verifies an $O(\log_2 N)$ SPV Merkle inclusion proof over TCP.
4. **Stage 4 (Worklet 1.5 — Double-Spend Prevention):** Submits two validly signed transactions spending the same UTXO and demonstrates authoritative rejection (`DoubleSpendError`).
5. **Stage 5 (Worklet 3 — Tamper Cascade, Fork Resolution & Persistence):** Modifies 1 byte in Block `#1`, traces the broken signature, Merkle root, and downstream links, demonstrates consensus rejection of the poisoned fork, and verifies `.bclt` disk persistence and on-disk tamper detection.
6. **Stage 6 (Worklet 3.5 — PoW Mining Benchmark):** Executes a live difficulty-vs.-time benchmark across $D \in \{0, 4, 8, 10\}$ leading zero bits.
