---
tags: [module, web, ui]
files: [web/static/index.html, web/static/app.css, web/static/app.js]
---
# mod — web frontend

Plain HTML / CSS / JS (no framework): `index.html` (792 lines), `app.css` (4070), `app.js` (1661). Cream-and-teal look. Pages via hash routes.

| Page | Route | What it shows |
|---|---|---|
| **Welcome** | `#welcome` | title, floating last-5 blocks, live capsule, page cards, **passcode vault** |
| **Explorer** | `#explorer` | next-block box, height/supply/tip, difficulty card, mining-effort chart, chain strip linked by `previous_hash`, send coins, mempool, wallets, block inspector (88-byte header + Merkle tree + SPV path), live events |
| **Block Forge** | `#forge` | 5 animated steps replayed from a real block: collect txs → SHA-256 + avalanche → Merkle tree → nonce search → append |
| **Tamper Lab** | `#tamper` | everyone's ledger copy; tamper one, see broken root/links, network check restores from majority |
| **People** | `#people` | add a person (RSA wallet + copy), manual tx, **Add block to blockchain** |

## Passcode vault
8 dashed blocks; each typed digit "seals" a block whose hash = SHA-256(prev hash + digit) — a mini hash chain. Right code → burst animation into the app; wrong → red alarm; 5 wrong → 30 s "Node locked". Unlock stored in `sessionStorage` per tab. Respects *reduce motion*.

## Live animations
Margin rails (≥ 1560 px): live chain cubes (left), next-block ghost cube with pending-tx chips (right). All motion follows real SSE events.

Full button-by-button guide: `docs/Frontend_Guide.md` (incl. a 10-minute demo script). Back-end: [[mod - web bridge]]. Back to [[Code Map]].
