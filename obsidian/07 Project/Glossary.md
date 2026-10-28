---
tags: [glossary]
---
# Glossary

| Term | Meaning | Note |
|---|---|---|
| Address | SHA-256 of a public key | [[Number Theory and RSA]] |
| Avalanche effect | 1 input bit flips ~half the output bits | [[SHA-256]] |
| Block height / index | position; Genesis = 0 | [[Block and Header]] |
| Coinbase | tx 0 of a block, mints the reward | [[Transactions]] |
| Cumulative work | Σ 2^difficulty; decides forks | [[Fork Resolution]] |
| Difficulty (D) | required leading zero bits; work 2^D | [[Proof-of-Work]] |
| Fee | inputs − outputs, goes to miner | [[Transactions]] |
| Genesis | block 0; starting balances; trust anchor | [[Chain Validation]] |
| Mempool | valid txs waiting to be mined | [[Mempool]] |
| Merkle root / proof | one hash for all txs / sibling hashes proving one | [[Merkle Tree]] |
| MTP | median-time-past of last 11 blocks | [[Difficulty Retargeting]] |
| Nonce | number the miner changes | [[Proof-of-Work]] |
| Retargeting | adjust difficulty toward a target block time | [[Difficulty Retargeting]] |
| SPV | verify inclusion with headers + Merkle proof | [[SPV Light Client]] |
| SSE | server-sent events, live stream to browser | [[mod - web bridge]] |
| Tip | latest block | |
| UTXO | unspent transaction output | [[UTXO Model]] |
| `.bclt` | the sealed chain file | [[Persistence]] |
