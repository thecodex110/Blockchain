---
tags: [module, web]
files: [web/network.py]
---
# mod — web network (simulated peers)

Simulates the part the single-node core leaves out: **many independent copies** of the chain.

- `Peer` — `name`, `blocks` (list), `tampered_block`, `repairs`, timestamps. Honest copies share the same immutable `Block` objects, so a copy costs one list.
- `LedgerNetwork`
  - `add_peer(name)`
  - `sync()` — gossip: append whatever the real ledger has that a copy lacks
  - `tamper(name, block, tx, amount)` — edits one tx amount in one copy, leaving the stored header untouched (so re-checks catch it)
  - `audit()` — the **network check** (every 20 s by default, `--audit-interval`): each copy is validated on its own (Merkle roots, header hashes, PoW, `previous_hash` links); **invalid copies can't vote**; valid copies are grouped by content; the **largest group is the majority**; every disagreeing copy is replaced → `ledger_repaired` event
  - `view()`, `blocks_of(name)`; per-block validation cache keyed by `id(block)`

This is a majority vote, not [[Fork Resolution]] (which uses cumulative work). Shown in the Tamper Lab page of [[mod - web frontend]]. Back to [[Code Map]].
