---
tags: [flow]
---
# Life of a Block

`BlockchainLedger.mine_pending_transactions(miner_address)`:

```mermaid
flowchart LR
  A[Collect mempool txs<br/>apply to cloned UTXO set<br/>sum fees] --> B[Coinbase at slot 0<br/>50 + fees, ts = height]
  B --> C[Merkle root<br/>leaves → root]
  C --> D[Header: index, prev hash,<br/>root, ts, scheduled D]
  D --> E[Nonce search<br/>outside state lock]
  E --> F[append_mined_block<br/>re-check under lock<br/>update UTXO, mempool, history]
```

1. **Collect** — every mempool tx, validated against a cloned [[UTXO Model|UTXO set]].
2. **Coinbase** — `block_reward (50) + fees`, height committed.
3. **Merkle root** — [[Merkle Tree]].
4. **Header** — difficulty from the schedule ([[Difficulty Retargeting]]).
5. **PoW** — [[Proof-of-Work]], outside the state lock so reads stay responsive.
6. **Append** — `append_mined_block` re-checks index, link, header/Merkle integrity, PoW, consensus; then updates the UTXO set, drops spent mempool txs, indexes address history.

These five steps are exactly what **Block Forge** animates ([[mod - web frontend]]) and what the Manim scenes render ([[mod - viz manim]]).
