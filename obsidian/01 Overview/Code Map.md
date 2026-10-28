---
tags: [overview, code-map]
---
# Code Map

Back to [[Home]] · see [[Architecture]].

## `blockchain_lite/` — core package (stdlib only)
| Path | Lines | What it does | Note |
|---|---:|---|---|
| `__init__.py` | 9 | `__version__ = "1.0.0"` | |
| `interfaces.py` | 198 | constants, exceptions, ABCs (`CanonicalSerializable`, `HashInterface`, `AsymmetricCryptoInterface`, `LedgerQueryInterface`), `MerkleProof`, `AvalancheReport` | [[mod - interfaces and serialization]] |
| `serialization.py` | 236 | `ByteBuffer` big-endian reader/writer | [[Canonical Serialization]] |
| `crypto/hashing.py` | 297 | `BitLevelSHA256`, round tracer, avalanche | [[SHA-256]] |
| `crypto/fast_hash.py` | 26 | `HashlibSHA256` (opt-in, only `hashlib` user) | [[SHA-256]] |
| `crypto/number_theory.py` | 291 | `pow_mod`, ext. GCD, `mod_inverse`, Miller–Rabin, prime gen | [[Number Theory and RSA]] |
| `crypto/asymmetric.py` | 298 | `RSAPublicKey`, `RSAPrivateKey`, `RSACryptoEngine` | [[Number Theory and RSA]] |
| `models/transaction.py` | 366 | `TxInput`, `TxOutput`, `Transaction`, double-spend checks | [[Transactions]] |
| `models/block.py` | 297 | `BlockHeader` (88 B), `Block` | [[Block and Header]] |
| `wallet/wallet.py` | 247 | `Wallet`: keys, coin selection, change, signing | [[mod - wallet]] |
| `wallet/demo_wallets.py` | 288 | 20 named wallets + Miner, Genesis + 10 pre-mined blocks | [[mod - wallet]] |
| `ledger/merkle.py` | 339 | `MerkleTree`, proofs, proof (de)serialization | [[Merkle Tree]] |
| `ledger/pow.py` | 210 | `ProofOfWorkMiner`, `verify_block_pow` | [[Proof-of-Work]] |
| `ledger/consensus.py` | 101 | `ConsensusParams`, `expected_difficulty`, timestamp rules | [[Difficulty Retargeting]] |
| `ledger/utxo.py` | 252 | `UTXOSet` hash map, atomic `apply_block` | [[UTXO Model]] |
| `ledger/validator.py` | 288 | `FullChainValidator`, `TamperCascadeReport` | [[Chain Validation]] |
| `ledger/chain.py` | 748 | `BlockchainLedger`: mempool, mining, forks, queries | [[mod - ledger]] |
| `ledger/persistence.py` | 242 | `.bclt` save/load, seal, atomic write | [[Persistence]] |
| `network/transport.py` | 82 | 4-byte length + JSON framing | [[mod - network]] |
| `network/server.py` | 453 | `LedgerServerDispatcher`, `TCPSocketLedgerServer` | [[mod - network]] |
| `network/client.py` | 244 | `WalletClient`, SPV | [[SPV Light Client]] |
| `network/web_dashboard.py` | 1699 | old single-file HTML dashboard (only used by `test_phase10`) | [[Legacy Code]] |
| `cli/terminal.py` | 499 | interactive console, menu 0–9 | [[mod - cli]] |
| `cli/demo.py` | 246 | 6-stage viva demo | [[Six-Stage Demo]] |
| `benchmarks/pow_benchmark.py` | 230 | difficulty vs time stats | [[mod - benchmarks]] |

## Around the package
| Path | What it does | Note |
|---|---|---|
| `web/bridge.py` | stdlib HTTP server, JSON API, SSE, AutoMiner | [[mod - web bridge]] |
| `web/network.py` | per-person ledger copies, tamper, majority audit | [[mod - web network]] |
| `web/gate.py` | 8-digit passcode front door | [[mod - web bridge]] |
| `web/static/` | `index.html`, `app.css`, `app.js` | [[mod - web frontend]] |
| `viz/scenes.py`, `viz/render.py` | Manim scenes + renderer | [[mod - viz manim]] |
| `tools/bundle.py` | builds `blockchain_lite_complete.py` | [[mod - tools bundle]] |
| `run_terminal.py`, `run/terminal.py` | console launchers | [[How to Run]] |
| `run_tests.py` | runs every test module | [[Test Suite]] |
| `tests/` | 14 test modules + attack scenarios | [[Test Suite]] |
| `docs/` | Project guide, frontend guide, protocol spec, HLD, RPC ref, viva guide | [[Viva Prep]] |
| `Dockerfile`, `docker-compose.yml` | container runs tests at build, then terminal | [[How to Run]] |
| `core/` | old separate prototype, unused | [[Legacy Code]] |
| `Blockchain_Project_Guide.txt` | Hinglish viva notes | [[Viva Prep]] |
| `Blockchain_Lite_Complete_Project_Report.pdf` | full project report | |
| `.claude/launch.json` | preview config: `python3 -m web.bridge --port 8080` | |
