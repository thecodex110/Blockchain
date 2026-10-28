# Security Policy & Threat Model

**Blockchain-Lite is educational software. Do not use it to hold or move real value.**

It exists to show how a blockchain works from first principles. Several choices that make it easy
to teach and fast to demo would be unacceptable in production. They are listed below.

## Reporting a problem

This is a course project with no production deployment. Open an issue on the repository, or tell
the project team directly. Please include the commit, the command you ran and what you observed.

## What the design protects against

Each of these is replayed in `tests/test_attack_scenarios.py` (defects D1–D8 from the 2026-10-15 audit)
or in the worklet test modules.

| Threat | Defence | Code |
| :--- | :--- | :--- |
| Editing a confirmed transaction | `tx_id` → Merkle root → block hash → next block's `previous_hash` all change; the signature stops verifying | `ledger/validator.py` |
| Double spending | UTXO set and mempool track every spent `(tx_id, output_index)` | `ledger/utxo.py`, `ledger/chain.py` |
| Spending someone else's coins | `SHA-256(public key)` must equal the output's owner, and the RSA signature must verify | `models/transaction.py` |
| Inflated block reward | Coinbase ≤ block reward + fees; reward comes from protocol parameters | `ledger/utxo.py` |
| Declaring an easy difficulty (D1) | Required difficulty is recomputed from chain history and must match exactly | `ledger/consensus.py` |
| Forged chain file (D2) | SHA-256 seal plus full re-validation under the caller's parameters on load | `ledger/persistence.py` |
| Duplicate coinbase IDs (D3) | Every non-genesis coinbase commits the block height | `ledger/consensus.py` |
| Timestamp manipulation (D8) | ≥ median of the previous 11 blocks, ≤ now + 2 h | `ledger/consensus.py` |
| Replacing the chain with a longer fake | Full validation first, then most cumulative work; Genesis must match | `ledger/chain.py` |
| Forged Merkle proof | Left/right direction checks and the odd-tail guard | `ledger/merkle.py` |
| Private keys sent to the server | Any RPC parameter named `*private_key*` is rejected; no method needs a key | `network/server.py` |
| Anyone mining over RPC | `mine_block` requires the server's `mine_token` | `network/server.py` |
| Oversized requests | 16 MiB frame cap (TCP), 64 KiB body cap (web bridge), per-client timeouts, bounded thread pool | `network/`, `web/bridge.py` |

## Known limitations

1. **Small RSA keys and a custom signature scheme.** Demo wallets use 384-bit keys and the classroom
   default is 512 bits, so keys generate in well under a second. Signatures are a deterministic,
   domain-separated encoding (`0x01 ‖ SHA-256(domain ‖ pubkey ‖ preimage) ‖ 0xBC`), not RSA-PSS.
   Production systems use ≥ 2048-bit RSA or elliptic curves through vetted libraries.
   `weak_key_warning` prints a warning below 2048 bits.
2. **No constant-time arithmetic.** Python big-integer operations leak timing, so signing is open to
   timing side channels.
3. **Key custody in the demos.** The terminal console and the web bridge hold the demo wallets'
   private keys in the same process as the ledger, so they can sign on a person's behalf.
   The proper design, where the wallet signs on its own side, is `network/client.py` (`WalletClient`).
4. **The web passcode is a front door, not access control.** The 8-digit passcode (demo default
   `12345678`) only decides whether the browser shows the app. The JSON API behind it stays open to
   anyone who can reach the bridge. The bridge binds to `127.0.0.1` by default; do not expose it on a
   network.
5. **SPV trusts its anchor.** `WalletClient.fetch_verified_headers` proves the headers form a valid
   proof-of-work chain from the Genesis hash you supply. It cannot detect a dishonest server hiding a
   heavier chain, and it is only as good as the Genesis hash you trust.
6. **A local attacker can rewrite a saved chain.** Someone with write access to a `.bclt` file can
   mine a new chain from a forged Genesis and re-seal it. Passing `expected_genesis_hash` to
   `ChainPersistence.load_ledger` defeats this.
7. **One node, no peer-to-peer network.** There is no gossip, peer discovery, Sybil resistance or
   Byzantine fault tolerance. The web app simulates many ledger copies inside one process.

See also [`docs/HLD_and_Interfaces.md`](docs/HLD_and_Interfaces.md) §6 and
[`docs/Project_Guide.md`](docs/Project_Guide.md) §13.
