---
tags: [concept, consensus, worklet/3]
aliases: [Forks, Most Cumulative Work]
---
# Fork Resolution

`BlockchainLedger.resolve_forks` in `ledger/chain.py` → `ForkResolutionOutcome`.

1. Each candidate chain is **fully validated** first ([[Chain Validation]]) — invalid chains lose however long they are.
2. Candidate must share the active **Genesis** (trust anchor, `F-001`).
3. Among valid chains, winner = most **cumulative work** `Σ 2^difficulty` (schedule-verified).
4. Tie → **current chain stays**.

Why "most work" not "longest": a long chain of difficulty-0 blocks is cheap. Attack D1 (difficulty-0 chain replacement) is replayed in `test_attack_scenarios` → [[Attack Defenses]].

The web app has no real peers, so it uses a separate **majority vote** among simulated copies instead → [[mod - web network]].
