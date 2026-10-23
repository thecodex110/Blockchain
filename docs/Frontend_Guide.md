# Blockchain-Lite — Frontend Guide

*What you see in the browser app, what every button does, and what happens behind it.*

For how the blockchain itself works, read [`Project_Guide.md`](Project_Guide.md) first or alongside.

---

## Contents

1. [Starting the app](#1-starting-the-app)
2. [The top bar](#2-the-top-bar)
3. [Explorer page](#3-explorer-page)
4. [Block Forge page](#4-block-forge-page)
5. [Tamper Lab page](#5-tamper-lab-page) and [People page](#5a-people-page)
6. [Live events: every message explained](#6-live-events-every-message-explained)
7. [A 10-minute demo script](#7-a-10-minute-demo-script)
8. [Behind the scenes: button → API → code](#8-behind-the-scenes-button--api--code)
9. [When something looks wrong](#9-when-something-looks-wrong)

---

## 1. Starting the app

```bash
python3 -m web.bridge
```

Open **http://127.0.0.1:8080**. On start the bridge builds a fresh demo chain (about 1 second): Genesis with 20 named wallets, 10 pre-mined blocks, and a **Miner** wallet that collects block rewards. Keys are random, so every restart gives different hashes. Nothing is saved when you stop the server.

Useful variations:

| Command | Effect |
| :--- | :--- |
| `python3 -m web.bridge --auto-mine` | Background mining starts immediately |
| `python3 -m web.bridge --retarget-interval 0` | Difficulty stays fixed at 4 bits |
| `python3 -m web.bridge --block-time 5` | Target 5 seconds per block instead of 10 |
| `python3 -m web.bridge --bit-level-hash` | Use the from-scratch SHA-256 (much slower, settles at a lower difficulty) |
| `python3 -m web.bridge --audit-interval 10` | Check everyone's ledger copy every 10 seconds instead of 20 |
| `python3 -m web.bridge --render` | Also render a Manim video of every new block (needs Manim) |

The app opens on a **welcome page** (§1.1). Behind it are four pages; switch with the pill menu at the top. The address bar shows `#explorer`, `#forge`, `#tamper` or `#people`, so you can bookmark a page — opening one of those addresses skips the welcome page.

### 1.1 Welcome page and the Open animation

Shown at `http://127.0.0.1:8080` (or `#welcome`), in the same cream-and-teal look as the app.

| Element | What it shows / does |
| :--- | :--- |
| **Welcome to the *Blockchain* Visualization Project** | The title, with a one-line description underneath |
| **Open** (teal, with pulsing rings) | Opens the app with an animation (below), then lands on the Explorer |
| **See what’s inside** / **What’s inside**, **From scratch** | Scroll down to the matching section of the welcome page |
| **GitHub** | Opens the project repository in a new tab |
| **Floating blocks** | The real last five blocks of the chain, joined by moving links. The bold leading zeros of each hash are its proof-of-work |
| **Black capsule** | Live numbers: height, current difficulty, and how many ledger copies are in sync |
| **Four cards** | Explorer, Block Forge, Tamper Lab, People — click one to jump straight to that page |
| **Built from first principles** | 122 tests, no third-party packages in the core, the number of ledger copies, and the difficulty range so far |

What **Open** does (about 2 seconds):
1. The button presses in and shrinks away; the text lifts up and blurs out.
2. The five blocks flash teal one after another, left to right.
3. Three rings spread out from the button.
4. A deep-teal circle grows from the button until it fills the screen.
5. The Explorer appears; the teal veil fades and the cards rise in one after another.

With the operating system's *reduce motion* setting on, **Open** goes straight to the Explorer. Click the **Blockchain-Lite** logo in the app to come back to the welcome page.

---

## 2. The top bar

| Element | What it shows / does |
| :--- | :--- |
| **Blockchain-Lite** logo | Goes back to the welcome page |
| **Explorer · Block Forge · Tamper Lab · People** | Page switcher. The raised pill is the page you are on |
| **Live pill** (black, right) | Connection to the bridge's live event stream. Pulsing teal dot + `Live · 127.0.0.1:8080` = connected. `Reconnecting…` = the stream dropped and the browser is retrying. `Bridge unreachable: …` = the server is not running |

---

## 3. Explorer page

The home page: the state of the chain, sending coins, and inspecting blocks.

### 3.1 Next block ring (top left)

| Element | Meaning |
| :--- | :--- |
| **Ring** | Fills as transactions wait in the mempool: one fifth for the coinbase, one more fifth per pending transfer (full at 4). It is a visual cue only; you can mine at any fill |
| **#N** | The height the next block will have |
| **"x tx waiting"** | Number of transfers in the mempool |
| Note under the ring | "x pending transfers + coinbase of 50 + fees" |
| **Mine & watch** | Mines the mempool into a new block right now, then jumps to **Block Forge** and plays its five steps automatically. While mining, the ring spins and the button is disabled. At high difficulty this can take several seconds |
| **Auto-mine** | Starts a background miner that keeps producing blocks, like a real network's hash power. The button turns black and reads **Auto-mining… stop**; press it again to stop (the current block finishes first). Use it to watch difficulty adjust (§3.3) |

### 3.2 Chain height, Total supply, Tip hash

| Card | Meaning |
| :--- | :--- |
| **Chain height** | Number of blocks including Genesis |
| **Total supply** | Sum of every unspent output. Starts at 9,200 and grows by 50 per mined block (fees only move coins, they do not create them) |
| **Tip hash** | Full hash of the newest block. The leading hex digits that Proof-of-Work forced to zero are shown in bold teal |
| **✓ Valid Genesis → tip** chip | Result of the full-chain validation. It turns red with ✗ if the chain were ever invalid |

### 3.3 Difficulty card

This card shows retargeting at work.

| Element | Meaning |
| :--- | :--- |
| **Big number + "bits"** | Current difficulty: how many leading zero bits a block hash needs. Each extra bit doubles the expected work |
| **next block pill** | Difficulty the next block must use. `= 18`: unchanged. Dark teal `↑ 19`: going up. Sand `↓ 17`: going down |
| **Chip (top right)** | `retarget in N blocks` — difficulty can only change every 4 blocks. `retargets on the next block` — this block is the checkpoint. `fixed difficulty` — retargeting is off |
| **Rule text** | Target time, the two thresholds, and the average time of the last 4 blocks |
| **Pace bar** | A scale from 0 to 2× the target. Left zone **too fast → +1** (under 7.5 s), middle **on target**, right zone **too slow → −1** (over 13.3 s). The black marker is where the last 4 blocks' average sits |

How to read it: if the marker is in the left zone when a retarget comes, difficulty goes up one bit; in the right zone, down one bit; in the middle, it stays.

### 3.4 Mining effort chart

Eight pill-shaped bars, one per recent block.

| Element | Meaning |
| :--- | :--- |
| **Number on top** | Hashes tried to find that block (`nonce + 1`), shortened: `193k`, `4.2M` |
| **Bar height** | The same number on a **log scale**, so a difficulty-22 block does not dwarf everything else |
| **#N / DN** | Block number and its difficulty |
| **Dark bar** | The currently selected block |

Click a bar to open that block in the inspector (§3.8). Expect randomness: a block at difficulty D needs `2^D` tries on average, but any single block can be lucky or unlucky.

### 3.5 Black gauge dock (right)

| Gauge | Meaning |
| :--- | :--- |
| **✓ 100% valid** | Chain validation result (`broken` if invalid) |
| **tx 0/10 mempool** | Pending transactions (the ring fills toward 10) |
| **D 4 bits difficulty** | Current difficulty out of the maximum (24) |
| **Round button** | Reloads everything from the bridge. Normally not needed; the page updates itself from live events |

### 3.6 The chain strip

A horizontal row of block cards joined by teal links, newest on the right. It scrolls sideways and jumps to the newest block when one arrives.

| On each card | Meaning |
| :--- | :--- |
| **#N** (or *Genesis*) | Block height |
| **"9 tx" chip** | Transactions in the block, including the coinbase |
| **hash** | This block's hash (first 8 … last 6 hex characters) |
| **prev** | The previous block's hash. It equals the *hash* on the card to its left: that is the chain |
| **merkle root** | Root of this block's Merkle tree |
| **nonce · D · time** | Winning nonce, difficulty, and seconds since the previous block |

- Click a card to inspect it (§3.8). The selected card gets a teal ring.
- New blocks slide in from the right.
- Only the last 12 blocks are drawn; a **+N earlier blocks** card at the left stands for the rest.
- The dashed card at the end is the block not yet mined.

### 3.7 Send coins

| Control | What it does |
| :--- | :--- |
| **From** circles | The sender. Each circle is a wallet's initial; hover to see name and balance. The pressed-in circle is selected |
| **To** | Recipient (any other wallet, including Miner) |
| **Amount** | Coins to send (whole numbers, at least 1) |
| **Fee** | Coins paid to the miner (default 1) |
| **Sender balance** | Read-only: the selected sender's current balance |
| **Sign & send from Alice** | The bridge picks the sender's UTXOs, adds change, signs with RSA, and submits the signed bytes through the same `submit_transaction` the TCP server uses |
| **Status box** | After a send: `Sent 8 to Bob · spent 1 UTXO · 1 change · tx ca1fb2ab`. On a problem it turns red with the reason, e.g. not enough funds, or an output already spent by a pending transaction |

The transaction then appears in **Mempool** and in **Live events**, and the next-block ring fills a step.

### 3.8 Mempool

Pending transactions: short `tx_id`, sender → recipient, amount. Empty shows "Quiet. Every transaction is already in a block." The list empties when a block is mined.

### 3.9 Block inspector

Shows whichever block you selected (the newest by default).

| Part | Meaning |
| :--- | :--- |
| **Block #N** | Title |
| **Watch how it was built →** | Opens Block Forge replaying this block |
| **Coloured bar** | The 88-byte header drawn to scale: index (4 B), previous hash (32 B), Merkle root (32 B), time (8 B), difficulty (4 B), nonce (8 B) |
| **Block hash / Previous / Merkle root** | Full 64-character hex values |
| **Nonce** | Winning nonce and how many hashes it took |
| **Time** | When it was mined, seconds after the previous block, and its difficulty |
| **Merkle tree** | Root on top (dark), leaves at the bottom, 8-character prefixes. Hover a node for the full hash. Scrolls sideways when wide |
| **Transactions** | Every transaction in the block: short `tx_id`, coinbase or sender → recipient, amount |

**Click a transaction** to see its Merkle proof:

- **Teal nodes** — the path from that transaction's leaf up to the root.
- **Outlined nodes** — the siblings: the hashes a light client needs to rebuild the root. With 9 transactions there are 4.
- The label reads `Proof for tx 2356e26c · 4 hashes · verified ✓`; the bridge checked the proof against the block header.

### 3.10 Live events

A black log at the bottom of the page, newest first (the last 40 are kept). Every line has a time, a coloured event name and details. See §6.

---

## 4. Block Forge page

An animated replay of how one block was built, step by step, using that block's real data.

### 4.1 Header controls

| Control | What it does |
| :--- | :--- |
| **Replay block** | Pick any block (newest first) to replay. Genesis is not listed: it is created, not mined |
| **Mine a new block** | Same as *Mine & watch*: mine now and play the new block from step 1 |

### 4.2 Step tabs

`01 Collect · 02 Hash · 03 Merkle · 04 Proof-of-Work · 05 Append`. Click a tab to jump to that step (this pauses playback). Finished steps are tinted, the current one is raised.

### 4.3 What each step shows

**01 Collect — gathering transactions**
- Left: up to 7 transactions sliding in. The dark one is the coinbase.
- Right: the *Candidate block* with one slot per transaction, filling in.
- Note: how many transactions, and what the coinbase pays the Miner (reward + fees).

**02 Hash — one transaction through SHA-256**
- *Canonical tx bytes*: the start of the real serialized transaction.
- The black **SHA-256 ring** counts rounds 0 → 64 while the `tx_id` types itself out on the right.
- `0x00 ‖ tx_id → leaf[i] = …`: how that `tx_id` becomes a Merkle leaf.
- **Avalanche** grid: 256 dots, one per output bit. The bridge flipped the last bit of the transaction bytes and hashed again; dark dots are the bits that changed (usually around 128). The title gives the exact count.

**03 Merkle — growing the tree**
- Rows from leaves up to the root, appearing level by level (leaves first, root last, with a halo).
- Chips: the parent rule `H(0x01 ‖ L ‖ R)`, the odd-tail rule, and how many hashes a proof needs.
- A block with a single transaction shows only the root (its root is the leaf).

**04 Proof-of-Work — searching for the nonce**
- Header bar: index, previous hash, Merkle root, time, `D=…`, and the **nonce** field ticking up.
- List of tries: `n=…`, the first 16 hex characters of that hash, and `×` (failed) or **FOUND** (dark teal row). These are real hashes: the bridge re-hashes the header with each nonce. For blocks that took more than 64 tries, only the last 64 are replayed, and the counter starts where they begin.
- Black capsule: a ring and counter of **hashes tried**, the target (first D bits zero, `hash < 2^(256−D)`), and the expected number of tries `2^D`.
- **Replay search** runs the nonce animation again.

**05 Append — joining the chain**
- The previous two blocks and the new block (dark, slides in), joined by links. Each card's *prev* equals the *hash* of the card on its left.
- Three cards: what the validator checked; the UTXO change (outputs spent and created); balances of Miner, Alice and Bob after this block.

### 4.4 Right panel

| Part | Meaning |
| :--- | :--- |
| **Ring "n/5"** | Current step |
| **Title + text** | Plain-language explanation, using this block's real numbers |
| **Code box** | The function in the project that does this step |
| **Manim scene** (black) | Which Manim scene animates this step and what it draws |
| **Video** | If a Manim render exists for this block, it plays here. Otherwise a note explains how to make one (`--render` or `python3 -m viz.render --block N`) |

### 4.5 Bottom controls

| Control | What it does |
| :--- | :--- |
| **← Back** | Previous step |
| **Play / Pause** | Plays the remaining steps automatically, then stops |
| **Progress bar** | How far through the five steps you are |
| **Next step →** / **Start over** | Next step; on step 5 it returns to step 1 |

---

## 5. Tamper Lab page

Every person in the network keeps **their own copy of the ledger**, like every node in a real blockchain. This page lets you edit one person's copy and watch the network notice and repair it.

### 5.1 Network check (black capsule, top right)

| Element | Meaning |
| :--- | :--- |
| **Ring + seconds** | Countdown to the next network check. By default every copy is checked every 20 seconds (`--audit-interval` changes it) |
| **Text** | How often the check runs, and the last result, e.g. `last: 20/21 valid, 1 repaired` |
| **Check now** | Runs the check immediately instead of waiting |

What the check does, in order:
1. Every copy first receives any new blocks (gossip).
2. Each copy is checked **on its own**: Merkle roots recomputed from the transactions, header hashes, Proof-of-Work, and every `previous_hash` link. A tampered copy fails here, so it **cannot vote**.
3. The valid copies are grouped by their exact content. The **largest group is the majority ledger**.
4. Every copy that differs from the majority is **replaced by it**. A notification and a log line report each repair.

### 5.2 Tamper with someone's copy

| Control | What it does |
| :--- | :--- |
| **Whose copy** | The person whose ledger you edit (everyone, including Miner and people you added) |
| **Block** | Which block in their copy (any block after Genesis) |
| **Transaction** | Which transaction in that block; the list shows sender → recipient · amount |
| **New amount** | The amount you write in. It starts at 100× the real amount |
| **Tamper** (red, ⚠) | Changes that transaction's first output in **only that person's copy**. The block header (its stored Merkle root and hash) is left as it was, exactly as if someone edited their own file. The real chain and everyone else's copies are untouched |

Right after **Tamper**:
- A red **notification** appears: *⚠ Grace's ledger copy was tampered … The network will check every copy in 9s.*
- The person's card in the grid turns red, shakes, and gets a pulsing **⚠ danger badge**: *⚠ block #6 changed*.

At the next network check:
- A teal **notification**: *✓ Tamper fixed: Grace's copy restored — 20 of 21 copies agreed, so Grace now holds that majority ledger again.*
- The card turns back with a teal ring and *↺ restored* for a few seconds, then *✓ N blocks*.

### 5.3 Everyone's ledger copy (grid)

One card per person: initial, name, and copy status.

| Card shows | Meaning |
| :--- | :--- |
| `✓ 12 blocks` | Copy is in sync and has 12 blocks |
| Red card, ⚠ badge, `⚠ block #6 changed` | Tampered, waiting for the network check |
| Teal ring, `↺ restored` | Just repaired from the majority |

The summary at the top right says `21 copies · all in sync` or `… · 1 tampered`.

### 5.4 What the tamper broke

After you tamper, three panels appear below the grid.

**Chain row** — the block before, the tampered block and up to three after, as seen in the tampered copy:

| Card | Badge | Shows |
| :--- | :--- | :--- |
| Before | **VALID** | Normal |
| Tampered block | **EDITED** (red) | The Merkle root recomputed from the edited transactions and the hash the block would need, both in red |
| Next block | **INVALID** | Its *prev* is struck through: it still points at the old hash. Link marked **broken** |
| Later blocks | **INVALID** | Built on a broken parent. Links marked **orphaned** |

After the repair the same row turns back to **VALID**, with the edited block marked **RESTORED**.

**What the tamper broke** card: whose copy; old → new amount; the transaction ID before and after; whether the signature still verifies (it does not: it signed the old amount); stored vs. recomputed Merkle root; the block hash change.

**Network check log** (black): what was changed, which checks fail in that copy, then — after the check — how many copies agreed, and that the copy was replaced and is back to the original amount.

The point: one person editing their copy changes nothing for anyone else. To make a change stick, an attacker would have to redo the Proof-of-Work for that block and every later block **and** get most people to hold the same edited copy.

---

## 5A. People page

Add people, make transactions by hand, and add blocks yourself.

### 5A.1 Add a person

| Control | What it does |
| :--- | :--- |
| **Name** | 1–20 letters, digits, spaces, `-` or `_`; must be new |
| **Starting coins from Miner** | Coins the Miner sends the new person (default 20; 0 for none) |
| **Add person** | Creates a fresh RSA wallet and address for them, gives them a full copy of the ledger (they now take part in every network check), and, if you asked for coins, submits a normal signed transfer Miner → them |

The status box shows the new address and *20 coins pending — add a block to deliver them*. A notification announces the new person. Until a block is added, their balance is 0.

### 5A.2 Manual transaction

| Control | What it does |
| :--- | :--- |
| **From / To** | Any two people (including new ones and the Miner). Clicking a card in **Everyone** also sets *From* |
| **Amount / Fee** | Coins to send and the fee for the miner |
| **Status box** | Shows the sender's balance; after sending, what was added; on a problem, the reason in red (for example *Insufficient spendable balance … available=0*) |
| **Add to pending** | Signs and submits the transfer. It waits in **Pending** until a block is added |

### 5A.3 Pending and **Add block to blockchain**

| Element | What it does |
| :--- | :--- |
| **Pending** list | Transactions waiting for the next block |
| **Add block to blockchain** | Mines every pending transaction into the next block at the current difficulty, then sends the block to every person's ledger copy. The note shows the block number, transaction count, nonce and hashes tried; a notification confirms it. With nothing pending it still adds a block containing only the Miner's reward |
| Auto-mine warning | If Auto-mine is on, blocks are also being added automatically. **Turn it off** stops it so you control every block |

### 5A.4 Everyone

A card per person: initial, name · balance, the start of their address, and whether their ledger copy is in sync or tampered. A newly added person is highlighted. Click a card to use that person as the sender.

---

## 6. Live events: every message explained

| Event | Colour | Example | Meaning |
| :--- | :--- | :--- | :--- |
| `tx_submitted` | light teal | `ca1fb2ab Alice → Bob · 8 (mempool 1)` | A signed transfer entered the mempool |
| `block_mined` | teal | `#73 00001a23…468229 · D18 · 193k hashes in 0.76s · 1 tx` | A block was mined: number, hash, difficulty, work, time, transaction count |
| `retarget` | sand / sage | `difficulty 17 → 18 bits · blocks averaged 0.7s (target 10s): too fast` | The difficulty schedule changed the next block's difficulty |
| `auto_miner` | light teal | `started` / `stopping after the current block` | Auto-mine was switched on or off |
| `copy_tampered` | coral | `Grace's copy · block #6 amount 12 → 1200` | Someone edited a person's ledger copy (Tamper Lab) |
| `network_check` | light teal | `20 of 21 copies valid · majority 20 · repaired 1` | The periodic network check ran |
| `ledger_repaired` | teal | `Grace's copy restored from the majority (20 of 21) · block #6` | A tampered copy was replaced with the majority ledger |
| `person_joined` | sand | `Ravi · e33ac445… · 20 coins pending` | A new person was added (People page) |
| `render_ready` | sand | `Manim video for #12` | A Manim render finished (only with `--render`) |
| `error` | coral | message text | The Auto-mine button could not reach the bridge or was refused |

Events come from the server, so if two browser tabs are open, both see every event.

---

## 7. A 10-minute demo script

1. **Explorer.** Point at the chain strip: each card's *prev* equals the hash on its left. Click block #5 and show its header bar and Merkle tree.
2. **Send coins.** Choose Alice → Bob, 8 coins, fee 1, then **Sign & send**. Show the status line (UTXO spent, change) and the transaction in Mempool and Live events.
3. **Merkle proof.** In the inspector, click a transaction and show the teal path and the 4 sibling hashes: "a phone wallet only needs these, not the whole block".
4. **Mine & watch.** Let Block Forge play all five steps. Pause on **Hash** for the avalanche grid and on **Proof-of-Work** for the failed tries and the FOUND row.
5. **Difficulty.** Back on Explorer, press **Auto-mine**. Watch the Difficulty card: blocks arrive far faster than 7.5 s, so every 4 blocks the difficulty rises a bit, `retarget` lines appear, and the effort bars grow. After a minute or so blocks take about 10 s. Press **Auto-mining… stop**.
6. **Tamper Lab.** Pick a person (say Grace), an older block and a transaction, and press **Tamper**. Show the red card with the ⚠ badge, the broken chain row and the log. Then press **Check now** (or wait for the countdown): the notification says the tamper was fixed and Grace's card shows *↺ restored*.
7. **People.** Add a person named Ravi with 20 coins, press **Add block to blockchain**, then send 5 from Ravi to Bob by hand and add another block.

---

## 8. Behind the scenes: button → API → code

| You press | Browser calls | Bridge does | Core code |
| :--- | :--- | :--- | :--- |
| (page load, refresh button) | `GET /api/state` | `BridgeState.state()` | `get_chain_info` RPC, `ledger.blocks`, `ledger.mempool`, `get_balance` |
| Block card / effort bar | `GET /api/block?index=N` | `block_detail` | `Block.compute_merkle_tree` |
| Transaction in inspector | `GET /api/proof?block=N&tx=I` | `merkle_proof` | `get_merkle_proof` RPC, `MerkleTree.verify_proof` |
| Sign & send | `POST /api/tx` | `send` | `Wallet.create_signed_transfer`, `submit_transaction` RPC |
| Mine & watch / Mine a new block | `POST /api/mine` | `mine` | `ledger.mine_pending_transactions`, `consensus.expected_difficulty` |
| Replay block | `GET /api/trace?index=N` | `forge_trace` | `Block.compute_header_hash(nonce_override=…)`, `hash_merkle_leaf` |
| Auto-mine | `POST /api/autominer` | `AutoMiner.start/stop` | repeated `mine_pending_transactions` |
| Tamper (a person's copy) | `POST /api/network/tamper` | `tamper_copy` → `LedgerNetwork.tamper` | edits one copy; `validator.trace_tamper_cascade` explains it |
| Check now / countdown | `POST /api/network/audit` | `LedgerNetwork.audit` | `Block.verify_crystallized_integrity`, `verify_block_pow`, majority vote |
| Ledger copy grid | `GET /api/network` | `LedgerNetwork.view` | — |
| Add person | `POST /api/people` | `add_person` | `Wallet.generate`, `LedgerNetwork.add_peer`, a normal transfer from Miner |
| Add to pending | `POST /api/tx` | `send` | `Wallet.create_signed_transfer`, `submit_transaction` RPC |
| Add block to blockchain | `POST /api/mine` | `mine` | `ledger.mine_pending_transactions`, `LedgerNetwork.sync` |
| (always open) | `GET /events` | `EventBus` | Server-Sent Events |

Front-end files: `web/static/index.html` (layout), `web/static/app.css` (look and animations), `web/static/app.js` (all behaviour). The bridge is `web/bridge.py`; everyone's ledger copies and the network check live in `web/network.py`.

---

## 9. When something looks wrong

| Symptom | Likely cause and fix |
| :--- | :--- |
| Live pill says *Bridge unreachable* | The server is not running. Start `python3 -m web.bridge` and reload |
| *Reconnecting…* after restarting the bridge | Reload the page: the restarted bridge has a brand-new chain |
| Mine takes a long time | Difficulty has climbed (each bit doubles the work). Wait, or restart the bridge to go back to difficulty 4 |
| Server log shows `Auto-miner retry: … exhausted 10000000 attempts` | At high difficulty the miner sometimes runs out of nonces for one timestamp. It retries with a new timestamp automatically; nothing is wrong |
| Send fails with *already spent by a pending transaction* | That wallet's coin is already used by a transaction in the mempool. Mine a block, or send from another wallet |
| Send fails with *Insufficient spendable balance* | Pick a smaller amount or another sender; hover the circles to see balances |
| No video in Block Forge | Manim is optional and not installed. See [`Project_Guide.md` §10](Project_Guide.md#10-manim-animations) |
| Supply keeps rising while Auto-mine runs | Expected: every block, even an empty one, pays the Miner 50 coins |
| A new person cannot send | Their starting coins arrive only in the next block: press **Add block to blockchain** first |
| A tampered copy is not repaired | Repair happens at the next network check (see the countdown), or press **Check now** |
