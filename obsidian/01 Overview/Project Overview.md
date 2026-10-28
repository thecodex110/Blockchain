---
tags: [overview]
---
# Project Overview

**Blockchain-Lite Ledger & Digital Wallet** — a small, working blockchain written from first principles in Python. Goal: *understanding*, not production. Back to [[Home]].

## "From first principles" means
| Usually you import… | Here it is hand-written in… | Note |
|---|---|---|
| `hashlib` SHA-256 | `crypto/hashing.py` | [[SHA-256]] |
| `cryptography` / `pycryptodome` RSA | `crypto/number_theory.py`, `crypto/asymmetric.py` | [[Number Theory and RSA]] |
| A blockchain SDK | `models/`, `ledger/` | [[Transactions]], [[Block and Header]], [[Merkle Tree]], [[Proof-of-Work]] |
| A database | `ledger/persistence.py` (`.bclt` file) | [[Persistence]] |
| A web / RPC framework | `network/` raw TCP + length-prefixed JSON | [[mod - network]] |

The `blockchain_lite` package imports **only the standard library**. `TestExclusionsCompliance` (in `test_phase1_foundation.py`) parses every module's AST and fails on any other import. The single allowed exception: `crypto/fast_hash.py` (wraps `hashlib`, bit-identical output, ~650× faster).

## Four ways to use it
1. **Interactive terminal console** — `python3 run_terminal.py` → [[mod - cli]]
2. **Automated 6-stage viva demo** — `python3 run_terminal.py --demo` → [[Six-Stage Demo]]
3. **Browser app** (Explorer, Block Forge, Tamper Lab, People) — `python3 -m web.bridge` → [[mod - web bridge]], [[mod - web frontend]]
4. **Manim videos** of a block being built — `viz/` → [[mod - viz manim]]

## Size (tracked files)
- ~85 tracked files, ~28.6k lines total.
- Biggest: `blockchain_lite_complete.py` (6.1k, generated bundle), `web/static/app.css` (4.1k), `network/web_dashboard.py` (1.7k, legacy), `web/static/app.js` (1.7k), `web/bridge.py` (781), `ledger/chain.py` (748).

## Related
[[Architecture]] · [[Worklets]] · [[Known Limitations]]
