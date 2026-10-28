---
tags: [moc, blockchain-lite]
aliases: [Index, MOC, Start Here]
---
# Blockchain-Lite — Home

> Educational, from-scratch **UTXO blockchain + RSA digital wallet** in pure Python standard library.
> COEP Technological University · CSE · Mini Project. Version `1.0.0`. **Not for real assets.**

Start with [[Project Overview]] → [[Architecture]] → [[Life of a Transaction]] → [[Life of a Block]].

## 01 Overview
- [[Project Overview]] — what, why, "from first principles"
- [[Architecture]] — layers and data flow (with diagrams)
- [[Worklets]] — how the work is split (W1 crypto, W2 blocks, W3 ledger, integration)
- [[Code Map]] — every file and what it does
- [[How to Run]] — terminal, demo, web app, Docker, tests

## 02 Concepts
- [[Canonical Serialization]] · [[SHA-256]] · [[Number Theory and RSA]]
- [[Transactions]] · [[UTXO Model]] · [[Mempool]]
- [[Merkle Tree]] · [[Block and Header]] · [[Proof-of-Work]]
- [[Difficulty Retargeting]] · [[Chain Validation]] · [[Fork Resolution]]
- [[Persistence]] · [[SPV Light Client]]

## 03 Modules
- Core package: [[mod - interfaces and serialization]] · [[mod - crypto]] · [[mod - models]] · [[mod - wallet]] · [[mod - ledger]] · [[mod - network]] · [[mod - cli]] · [[mod - benchmarks]]
- Around the package: [[mod - web bridge]] · [[mod - web network]] · [[mod - web frontend]] · [[mod - viz manim]] · [[mod - tools bundle]]
- [[Legacy Code]] — `core/` and the old `web_dashboard.py`

## 04 Flows
- [[Life of a Transaction]] · [[Life of a Block]] · [[Tamper Cascade]] · [[Six-Stage Demo]]

## 05 Security
- [[Attack Defenses]] · [[Known Limitations]]

## 06 Testing
- [[Test Suite]]

## 07 Project
- [[Requirements Matrix]] · [[Timeline and History]] · [[Review Findings]] · [[Glossary]] · [[Viva Prep]]

## Quick facts
| | |
|---|---|
| Language | Python ≥ 3.11 (also runs on 3.9.6 locally) |
| Dependencies | none (stdlib only; `hashlib` only in opt-in `fast_hash.py`) |
| Tests | 126 tests, 14 modules, 1 skipped — all pass (~41 s) |
| Hash | bit-level FIPS 180-4 SHA-256 (fast hashlib backend optional, ~650× faster) |
| Signatures | custom RSA, demo keys 384-bit |
| Consensus | PoW, leading-zero-bit difficulty, most cumulative work wins |
| Block header | 88 bytes |
| Block reward | 50 coins |
| Repo | `thecodex110` on GitHub, branch `main` |
