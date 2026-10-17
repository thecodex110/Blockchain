# Blockchain-Lite Ledger & Digital Wallet (Terminal Edition)

**COEP Technological University · Department of Computer Science and Engineering**
*A Foundations-First Framework Implementation (Python 3.9+, Standard Library Only)*

> **Educational Software Notice:** Built completely from scratch for academic evaluation. No external cryptography libraries (OpenSSL, PyCryptodome), web frameworks, or third-party databases are used.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Terminal Console & Menu Options](#2-terminal-console--menu-options)
3. [How to Run](#3-how-to-run)
4. [Worklet Implementation Mapping](#4-worklet-implementation-mapping)

---

## 1. Executive Summary

This repository implements an interactive, terminal-driven, tamper-evident blockchain ledger and digital wallet, built directly from mathematical and computer-science first principles. It ships with a zero-dependency REPL console that lets you create transactions, mine blocks, verify Merkle proofs, and watch tampering get rejected.

---

## 2. Terminal Console & Menu Options

### Console Preview

```text
================================================================================
 BLOCKCHAIN-LITE LEDGER & DIGITAL WALLET — TERMINAL CONSOLE
 Python Standard Library · Pure First-Principles Blockchain
================================================================================

--- [ MAIN MENU ] -------------------------------------------------------------
 [1] Chain Status        - View height, latest block hash, difficulty & mempool
 [2] Explore Blocks      - List all blocks and view detailed transactions
 [3] Wallets & Balance   - View demo wallet addresses, UTXOs & balances
 [4] Send Transfer       - Create & sign a transaction with RSA private key
 [5] Mine Block          - Mine pending transactions via Proof-of-Work
 [6] Verify Merkle Proof - Generate & verify O(log N) SPV inclusion proof
 [7] Simulate Tamper     - Tamper 1 byte and witness cryptographic rejection
 [8] Run Full Demo       - Execute 6-stage automated viva evaluation suite
 [9] PoW Benchmark       - Difficulty vs mining time statistical profiler
 [0] Exit Console        - Quit the terminal session
--------------------------------------------------------------------------------
Select option [0-9]:
```

### Option Details

| Option | Name | Key Technical Mechanics |
|:------:|------|-------------------------|
| **1** | Chain Status | Validates genesis-to-tip integrity, calculates total Nakamoto cumulative work (Σ 2^difficulty), and monitors mempool status. |
| **2** | Explore Blocks | Inspects 88-byte block headers (`version`, `prev_hash`, `merkle_root`, `timestamp`, `difficulty`, `nonce`) and transaction structures. |
| **3** | Wallets & Balance | Scans the in-memory hash-map `UTXOSet` for O(1) unspent-balance retrieval across demo addresses. |
| **4** | Send Transfer | Performs deterministic UTXO coin selection, computes change outputs, and generates RSA digital signatures over canonical preimages. |
| **5** | Mine Block | Bundles mempool transactions, constructs binary Merkle trees, and runs a nonce search until the SHA-256 target difficulty is satisfied. |
| **6** | Verify Merkle Proof | Generates O(log N) light-client (SPV) audit paths with domain-separation prefixes (`0x00` leaf / `0x01` internal). |
| **7** | Simulate Tamper | Mutates 1 byte in a historical block to demonstrate the full failure cascade: Signature → Merkle Root → Header → Chain Link. |
| **8** | Run Full Demo | Executes the automated 6-stage viva evaluation suite across all core cryptographic and consensus worklets. |
| **9** | PoW Benchmark | Profiles mining time vs. difficulty target and compares the pure bitwise SHA-256 against the standard-library backend. |
| **0** | Exit Console | Cleanly terminates active thread pools and saves state to disk. |

---

## 3. How to Run

### Prerequisites

- Python **3.9+** (standard library only, nothing to `pip install`)

### Commands

**1. Launch the interactive terminal REPL console**

```bash
python3 main.py --cli
# OR
python3 -m blockchain_lite.cli.demo --interactive
```

**2. Run the automated 6-stage viva evaluation demo**

```bash
python3 main.py --demo
```

**3. Run the unit test suite**

```bash
python3 -m unittest discover tests/
```

**4. Run the Proof-of-Work profiler benchmark**

```bash
python3 -m blockchain_lite.benchmarks.pow_benchmark
```

---

## 4. Worklet Implementation Mapping

### Worklet 2: Blocks, Bitwise Hashing, Merkle Trees & PoW (DLCO + DSA)

| Component | File | Description |
|-----------|------|-------------|
| 32-Bit Bitwise SHA-256 Engine | `blockchain_lite/crypto/hashing.py` | Pure 32-bit bitwise implementation of Ch, Maj, Σ0, Σ1, σ0, σ1 per FIPS 180-4, tested with the Strict Avalanche Criterion. |
| Binary Merkle Tree | `blockchain_lite/ledger/merkle.py` | Domain-separated (`0x00` leaf, `0x01` internal) tree builder with O(log₂ N) inclusion proofs and odd-tail spoofing defense. |
| Block Chaining & Headers | `blockchain_lite/models/block.py` | Fixed 88-byte binary headers linked sequentially via predecessor hashes (`previous_hash`). |
| Proof-of-Work Engine | `blockchain_lite/ledger/pow.py` | Nonce-search worker operating on leading-zero-bit difficulty schedules. |

### Worklet 3: Full Validation, UTXOSet, Fork Resolution & Persistence

| Component | File | Description |
|-----------|------|-------------|
| Genesis-to-Tip Chain Validator | `blockchain_lite/ledger/validator.py` | One-pass verification of block links, difficulty targets, and transaction signatures. |
| Hash-Map UTXOSet | `blockchain_lite/ledger/utxo.py` | State tracker for O(1) balance queries and double-spend detection. |
| Nakamoto Fork Resolution | `blockchain_lite/ledger/chain.py` | Resolves competing chains by choosing the branch with the highest cumulative difficulty (Σ 2^difficulty). |
| Tamper-Evident Binary Persistence | `blockchain_lite/ledger/persistence.py` | Atomic `.bclt` state serialization with mandatory genesis-to-tip re-validation on reload. |
