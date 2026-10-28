---
tags: [testing]
---
# Test Suite

`python3 run_tests.py` → **126 tests, 14 modules, 1 skipped, all OK** (~41 s on Python 3.9.6, checked 2026-10-28). Plain `unittest`, no pytest needed.

| Module | Covers | Notes |
|---|---|---|
| `test_phase1_foundation` | interfaces, constants, `ByteBuffer`, **stdlib-only AST import audit** (`TestExclusionsCompliance`), SHA-256 vectors | [[Canonical Serialization]], [[SHA-256]] |
| `test_phase2_worklet1` | number theory, Miller–Rabin, RSA, txs, wallet signing | [[Number Theory and RSA]] |
| `test_phase3_worklet2` | SHA-256, Merkle trees/proofs, blocks, chaining, PoW | [[Merkle Tree]], [[Proof-of-Work]] |
| `test_phase4_worklet3` | full validation, forks, UTXO, persistence | [[Chain Validation]] |
| `test_phase5_integration` | client/server, in-memory + real TCP | [[mod - network]] |
| `test_phase6_defensive_verification` | defensive cases A–G | |
| `test_phase7_advanced_features` | retargeting, address history | [[Difficulty Retargeting]] |
| `test_phase9_core_engineering` | non-blocking mining, mining auth, incremental mempool | [[Mempool]] |
| `test_phase10_dashboard_ui` | old dashboard markup | [[Legacy Code]] |
| `test_phase11_fast_hash` | fast backend bit-identical (1 slow test skipped unless `BLOCKCHAIN_LITE_SLOW_TESTS=1`) | |
| `test_phase12_serialization_properties` | randomised round-trip + mutation | |
| `test_phase13_spv_and_keys` | SPV header chain, 2048-bit keys | [[SPV Light Client]] |
| `test_attack_scenarios` | D1–D8 replayed | [[Attack Defenses]] |
| `test_terminal_console` | every menu action | [[mod - cli]] |
| `test_web_bridge` | API, SSE, static, auto-miner, retarget up/down, copies tamper→repair, people, passcode gate | [[mod - web bridge]] |

Tooling (dev only): coverage gate **86 %** line+branch (`pyproject.toml`, ratchet), ruff, mypy. Docker build runs the suite too.

> No test module is numbered `phase8`. Note: `run_tests.py` lists modules explicitly, so a new test file must be added there.
