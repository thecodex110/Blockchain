---
tags: [concept, worklet/2, consensus]
aliases: [PoW, Mining]
---
# Proof-of-Work

Making a block must cost real compute, so rewriting history is expensive. File: `ledger/pow.py`.

- Miner tries `nonce = 0, 1, 2, …`, hashing the 88-byte header, until `hash < 2^(256 − D)` ⇔ the first **D bits are zero**.
- Each try succeeds with probability `2^−D` → expected `2^D` tries (Geometric distribution). D=4 ≈ 16 tries; D=20 ≈ 1M.
- `count_leading_zero_bits`, `target_for_difficulty`, `hash_meets_difficulty`, `verify_block_pow`
- `ProofOfWorkMiner.mine_block_with_stats` → `MiningStats` (hashes tried, time, rate)
- D ∈ [0, 256]; consensus clamps to [1, 24]. RPC `mine_block` refuses D > 20.
- Mining runs **outside** the ledger state lock (fix D7).

Difficulty is chosen by [[Difficulty Retargeting]]. Measured in [[mod - benchmarks]].

> Signature ≠ PoW: a signature proves *who* authorised a tx; PoW proves *work was spent* on a block (viva Check 5).
