---
tags: [module, worklet/1]
files: [blockchain_lite/wallet/wallet.py, blockchain_lite/wallet/demo_wallets.py]
---
# mod — wallet

## `Wallet` (`wallet.py`)
- Constructors: `generate(label, bits)`, `from_private_key_bytes`, `watch_only` (public key only, `can_sign = False`).
- `address` = SHA-256 of public key; `sign_bytes`, `verify_bytes`, `sign_transaction`.
- **`create_signed_transfer(recipient, amount, fee, spendable_utxos)`** — sorts UTXOs deterministically by amount, selects enough for `amount + fee`, adds a change output, signs every input. Raises *Insufficient spendable balance*.
- `SpendableUTXO` dataclass.
- Private keys stay on the client — the server never receives them ([[mod - network]]).

## Demo data (`demo_wallets.py`)
`create_demo_ledger_and_wallets(...)` → 20 named wallets (Alice, Bob, Grace, …) + **Miner**; Genesis funds them 300–500 each (9,200 total); 10 pre-mined blocks × 8 transfers. Optional retargeting; demo blocks are back-dated at an even pace so they don't move difficulty. Used by terminal, demo and web bridge.

> [!note] In the terminal and web app the demo wallets live in the same process as the ledger — a classroom convenience, not real custody. See [[Known Limitations]].

Back to [[Code Map]].
