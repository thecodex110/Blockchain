---
tags: [module, ui]
files: [blockchain_lite/cli/terminal.py, blockchain_lite/cli/demo.py, run_terminal.py]
---
# mod — cli

## Terminal console (`terminal.py`, `TerminalConsole`)
Cream / burgundy / olive ANSI theme. Menu:

| Key | Action | Method |
|---|---|---|
| 1 | Chain status | `show_chain_status` |
| 2 | Explore blocks | `list_blocks`, `inspect_block` |
| 3 | Wallets & balance | `show_wallets` |
| 4 | Send transfer (RSA-signed) | `send_transfer` |
| 5 | Mine block | `mine_block` |
| 6 | Verify Merkle proof (SPV) | `verify_merkle_proof` |
| 7 | Simulate 1-byte tamper | `simulate_tamper` |
| 8 | Run 6-stage demo | `run_demo` |
| 9 | PoW benchmark | `run_benchmark` |
| 0 | Exit | |

Launch: `python3 run_terminal.py [--fast-hash|--demo|--status]` (also `run/terminal.py`, `python -m blockchain_lite.cli`, script `blockchain-lite-terminal`).

## Demo (`demo.py`)
`run_complete_demonstration(rsa_bits)` → [[Six-Stage Demo]]. Script `blockchain-lite-demo`.

Tests: `test_terminal_console`. Back to [[Code Map]].
