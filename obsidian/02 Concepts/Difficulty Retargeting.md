---
tags: [concept, consensus, worklet/3]
aliases: [Retargeting, Consensus Rules, ConsensusParams]
---
# Difficulty Retargeting

File: `ledger/consensus.py` — the **single source of truth** for consensus rules.

## `ConsensusParams` (frozen dataclass)
| Field | Default |
|---|---|
| `initial_difficulty` | 8 |
| `block_reward` | 50 |
| `retarget_interval` | 0 (= fixed difficulty) |
| `target_block_time_seconds` | 10.0 |
| `min_difficulty` / `max_difficulty` | 1 / 24 |

Params can't change after Genesis.

## `expected_difficulty(blocks_so_far, params)`
- interval ≤ 0 or fewer blocks than interval → `initial_difficulty`
- not on a retarget boundary → same as the previous block
- on a boundary: `actual = ts[-1] − ts[-interval]`, `target = interval × block_time`
  - `actual < 0.75 × target` → **+1 bit** (2× work)
  - `actual > 1.33 × target` → **−1 bit**
  - else unchanged; clamped to [min, max]

**Computed from history, never trusted from the block.** A block that declares any other difficulty is rejected (`TamperDetectedError`) — fix D1.

## Timestamp rules (`check_timestamp`)
- ≥ **median-time-past** of the last 11 blocks
- ≤ now + **2 hours**
So miners can't fake fast/slow blocks to steer difficulty (fix D8).

## Coinbase height commitment
Non-genesis coinbase must store `block.index` in its `timestamp` (fix D3).

## In the web app
Bridge target 10 s, interval 4; window spans `interval − 1` gaps so the bridge scales the param to 7.5 s → real thresholds **7.5 s** (+1) and **13.3 s** (−1). With Auto-mine on the fast backend, difficulty climbs from 4 to ~21–22 bits (~250k H/s). One bit per interval is gentle — Bitcoin adjusts up to 4× per period ([[Known Limitations]]).
