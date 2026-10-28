---
tags: [flow, demo, viva]
---
# Six-Stage Demo

`python3 run_terminal.py --demo` or `python -m blockchain_lite.cli.demo [--rsa-bits N]` (`cli/demo.py`).

| Stage | Worklet | Shows |
|---|---|---|
| 1 | W1 number theory & RSA | square-and-multiply trace (272 ops, 256-bit exponent); Carmichael numbers 561, 1105, 1729, 2465, 6601 rejected; client wallets |
| 2 | Client-server + W3.3 | `TCPSocketLedgerServer` on 127.0.0.1 with demo mine token; `WalletClient` balances; signed transfers over TCP; mine block #1; balances reconcile |
| 3 | W2 avalanche + SPV | ~50 % bit flips from a 1-bit change; O(log N) Merkle proof over TCP |
| 4 | W1.5 double spend | two signed txs spending the same UTXO → `DoubleSpendError` |
| 5 | W3 tamper, forks, persistence | 1-byte tamper in block #1 → [[Tamper Cascade]]; poisoned fork rejected; `.bclt` save + on-disk tamper detected |
| 6 | W3.5 benchmark | difficulty vs time for D ∈ {0, 4, 8, 10} |

Related: [[Viva Prep]], [[Requirements Matrix]].
