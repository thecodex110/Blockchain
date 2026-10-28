---
tags: [viva, project]
---
# Viva Prep

Source: `docs/Viva_Guide_and_Design_Journal.md` (+ Hinglish notes in `Blockchain_Project_Guide.txt`). Final viva **4–6 Nov 2026**.

## 5 official learning-outcome checks
1. Why is modexp cheap but factoring / discrete log hard? → [[Number Theory and RSA]]
2. Change one byte of one tx — what breaks? → [[Tamper Cascade]]
3. What does a Merkle proof prove; size for N txs? → [[Merkle Tree]] (⌈log₂ N⌉)
4. Why does `previous_hash` make the chain tamper-evident? → [[Block and Header]]
5. Signature vs proof-of-work guarantees? → [[Proof-of-Work]]

## 19 technical questions (short answers)
1. Fast modexp — square-and-multiply, ≤ 2·log₂e + 1 multiplications.
2. RSA assumption — integer factorisation is hard.
3. Private key vs password hash — a key can *sign*; a hash only checks equality.
4. Signature covers — domain tag `BCLT-RSA-SHA256-V1|` + public key + unsigned tx bytes.
5. Signed tx changes → preimage changes → signature fails.
6. `tx_id` = SHA-256 of full serialized tx (incl. signatures).
7. Merkle proof — tx at index i is committed by the header's root.
8. PoW check — hash the 88-byte header, compare against `2^(256−D)`.
9. Why validate from Genesis — UTXO state depends on every earlier block. → [[Chain Validation]]
10. Local ledger can still be rewritten — hashes make it *detectable/expensive*, not impossible.
11. Balances come from the selected valid chain's UTXO set. → [[UTXO Model]]
12. Forks can change balances — UTXOs exist only on their branch.
13. Most-work vs longest chain → [[Fork Resolution]]
14. Client-server guarantees — server can't forge signatures; still trusted for availability/ordering.
15. Not production — small RSA, one node, Python speed. → [[Known Limitations]]
16. Difficulty from history (D1) → [[Difficulty Retargeting]]
17. Coinbase height (D3) → [[Transactions]]
18. Timestamp rules (D8) → [[Difficulty Retargeting]]
19. Anchored SPV proves / doesn't prove → [[SPV Light Client]]

## 5 design pitfalls & mitigations
Slow modexp · Merkle odd-tail spoofing (F-003) · `previous_hash` as decoration · confusing signatures with PoW · reloading without re-validating (F-001/F-005 → [[Persistence]]).

## Good live demos
- [[Six-Stage Demo]]
- Attacks: difficulty-0 chain replacement (D1), forged 10¹⁵-coin file (D2), cross-site POST (D5), read-while-mining (D6) — `python -m unittest -v tests.test_attack_scenarios`
- Web 10-minute script in `docs/Frontend_Guide.md` §7 ([[mod - web frontend]])
