---
tags: [concept, worklet/3]
aliases: [BCLT, .bclt]
---
# Persistence

File: `ledger/persistence.py`, class `ChainPersistence`.

## `.bclt` format
`"BCLT"` magic + version + header values (difficulty, reward …) + every block + **SHA-256 seal** over everything.

## Save
Write `<target>.tmp` → `fsync` → atomic `os.replace` → a crash mid-write can't corrupt the old file.

## Load
1. Check the seal.
2. **Re-validate the whole chain** under the *caller's* protocol params (never the file header's) — fix D2 (a forged 10¹⁵-coin file is rejected).
3. Optional `expected_genesis_hash` pin.

Pitfall 5 in the design journal: "reloading a persisted chain without re-validating". See [[Attack Defenses]].
