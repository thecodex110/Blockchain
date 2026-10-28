---
tags: [security]
---
# Attack Defenses

`tests/test_attack_scenarios.py` replays each attack (D1–D8 from the 2026-10-15 audit) and shows it fails.

| Attack | What stops it | Where |
|---|---|---|
| Edit an amount in an old tx | tx_id → root → hash → next `previous_hash` mismatch; signature fails | `validator.py` — [[Tamper Cascade]] |
| Double spend | UTXO set + mempool track spent outpoints | `utxo.py`, `chain.py` — [[UTXO Model]], [[Mempool]] |
| Spend someone else's coins | `SHA-256(pubkey)` = owner + signature | `transaction.py` |
| Pay yourself a huge reward | coinbase ≤ reward + fees | `utxo.apply_block` |
| Claim easy difficulty (**D1**) | difficulty recomputed from history | `consensus.py` — [[Difficulty Retargeting]] |
| Forged saved file (**D2**, 10¹⁵ coins) | seal + re-validation under caller params | [[Persistence]] |
| Duplicate coinbase ids (**D3**) | coinbase commits height | `consensus.py` |
| Cross-site POST to old dashboard (**D5**) | `X-API-Token` + JSON content type, no CORS wildcard | `web_dashboard.py` ([[Legacy Code]]) |
| Fake timestamps (**D8**) | median-time-past, ≤ now + 2 h | `consensus.py` |
| Longer fake chain | full validation, then most work, Genesis pinned | [[Fork Resolution]] |
| Fake Merkle proof | direction checks + odd-tail guard | [[Merkle Tree]] |
| Edit own ledger copy (web) | copy fails checks, can't vote, replaced by majority | [[mod - web network]] |
| Send private key to server | rejected by name | [[mod - network]] |
| Mining over RPC by anyone | `mine_token` required | `server.py` |

See also [[Known Limitations]].
