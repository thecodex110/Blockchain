---
tags: [flow]
---
# Life of a Transaction

Example: **Alice sends 8 coins to Bob, fee 1.**

```mermaid
sequenceDiagram
  participant W as Alice's Wallet (client)
  participant S as Ledger server
  participant M as Mempool
  participant B as Next block
  W->>S: get_utxos(alice)
  S-->>W: [10-coin UTXO, ...]
  Note over W: select 10 ≥ 8+1<br/>outputs: 8→Bob, 1→Alice (change)<br/>fee = 10 − 9 = 1
  Note over W: sign signing_preimage_bytes<br/>with RSA private key
  W->>S: submit_transaction(tx_bytes_hex)
  S->>S: checks: not coinbase, ts sane, UTXO exists & unclaimed,<br/>SHA-256(pubkey)=owner, signature, value, fee
  S->>M: add (claims outpoint)
  M->>B: mined (see Life of a Block)
  Note over B: input removed from UTXO set,<br/>2 outputs added
```

1. **Find coins** — `get_spendable_utxos(alice)` ([[UTXO Model]]).
2. **Build** — `Wallet.create_signed_transfer` ([[mod - wallet]]).
3. **Sign** — over the preimage without signatures ([[Transactions]], [[Number Theory and RSA]]).
4. **Submit** — over TCP or via the web bridge ([[mod - network]]).
5. **Wait** — [[Mempool]].
6. **Mined** — [[Life of a Block]].
7. **Final** — Bob's balance includes 8; inclusion provable with a 4-hash Merkle proof ([[SPV Light Client]]).
