---
tags: [module, legacy]
files: [core/ledger.py, core/validation.py, blockchain_lite/network/web_dashboard.py]
---
# Legacy Code

## `core/` (105 lines)
An older, separate prototype: its own `BlockchainLedger` (`resolve_fork`, `persist_to_disk`, `reload_and_validate`), `UTXOSet` (float balances, string addresses) and `FullChainValidator`. **Nothing in the package or tests imports it.** Candidate for deletion or an `archive/` folder.

## `blockchain_lite/network/web_dashboard.py` (1699 lines)
The previous single-file HTML dashboard (`WebDashboardServer`, `X-API-Token` POSTs — fixes D5/D6). Commit `88867ec` ("Terminal-only: remove web dashboard frontend completely") removed the frontend wiring, and the new browser app is [[mod - web bridge]]. Today it is only imported by `tests/test_phase10_dashboard_ui.py` (markup checks). It also isn't in the bundle.

See [[Review Findings]]. Back to [[Code Map]].
