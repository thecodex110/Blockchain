---
tags: [security, limitations]
---
# Known Limitations

- **Educational crypto** — 384/512-bit RSA, custom non-constant-time signature scheme. Real systems: ≥ 2048-bit RSA or ECC with vetted libs. (`weak_key_warning` warns below 2048.)
- **One node** — no real P2P or competing miners. Web app simulates peers in one process ([[mod - web network]]).
- **Demo custody** — terminal & web app hold demo private keys in the ledger process.
- **Passcode ≠ access control** — the JSON API is open to anyone who can reach the bridge (loopback by default).
- **Gentle retargeting** — ±1 bit per interval; 4 → 22 bits takes ~70 blocks.
- **Python speed** — ~1k H/s from scratch, 250k–600k H/s fast backend.
- **Manim renders untested** locally.
- **Python version** — targets 3.11+, but dev machine runs 3.9.6 (tests pass there too).
- Full threat model now lives in `SECURITY.md` (fixed 2026-10-28, see [[Review Findings]]).
