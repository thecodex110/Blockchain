# Blockchain-Lite — The Complete Project Guide

*What this project is, what happens inside it, and how each part works. Read it top to bottom once; after that, use the table of contents to jump around.*

For button-by-button help with the browser app, see [`Frontend_Guide.md`](Frontend_Guide.md). For exact byte layouts and consensus rules, see [`Protocol_and_Architecture_Specification.md`](Protocol_and_Architecture_Specification.md).

---

## Contents YES ME :

1. [What this project is](#1-what-this-project-is)
2. [The big picture](#2-the-big-picture)
3. [The building blocks, one idea at a time](#3-the-building-blocks-one-idea-at-a-time)
4. [The life of a transaction](#4-the-life-of-a-transaction)
5. [The life of a block](#5-the-life-of-a-block)
6. [Difficulty retargeting](#6-difficulty-retargeting)
7. [How the chain defends itself](#7-how-the-chain-defends-itself)
8. [Where everything lives (code map)](#8-where-everything-lives-code-map)
9. [The web frontend and bridge](#9-the-web-frontend-and-bridge)
10. [Manim animations](#10-manim-animations)
11. [How to run everything](#11-how-to-run-everything)
12. [Tests](#12-tests)
13. [Limits and honest caveats](#13-limits-and-honest-caveats)
14. [Glossary](#14-glossary)

---

## 1. What this project is

**Blockchain-Lite** is a small, working blockchain and digital wallet written from first principles in Python. It is an educational project (COEP Technological University, CSE), so the goal is understanding, not production use.

"From first principles" means the project does not borrow the hard parts:

| Usually you would import… | Here it is written by hand in… |
| :--- | :--- |
| SHA-256 (`hashlib`) | `crypto/hashing.py`: bit-level FIPS 180-4 SHA-256 |
| RSA (`cryptography`, `pycryptodome`) | `crypto/number_theory.py` + `crypto/asymmetric.py`: primes, Miller–Rabin, modular inverse, RSA keys and signatures |
| A blockchain SDK | `models/`, `ledger/`: transactions, blocks, Merkle trees, Proof-of-Work, UTXO set, validation, fork choice |
| A database | `ledger/persistence.py`: a sealed binary `.bclt` file |
| A web/RPC framework | `network/`: raw TCP sockets with length-prefixed JSON |

The `blockchain_lite` package uses **only the Python standard library**. A test (`TestExclusionsCompliance`) parses every module and fails if anything else is imported. The one allowed exception is `crypto/fast_hash.py`, an optional `hashlib` backend that produces exactly the same bytes but is about 650× faster.

Around that core there are four ways to use it:

- an **interactive terminal console** (`run_terminal.py`),
- an **automated 6-stage demo** for the viva (`run_terminal.py --demo`),
- a **browser frontend** with live visualizations (`python3 -m web.bridge`),
- **Manim videos** of how a block is built (`viz/`).

---

## 2. The big picture

```text
   ┌────────────────────────────── USERS ──────────────────────────────┐
   │  Browser (web/static)     Terminal console (cli/)     Demo (cli/) │
   └─────────────┬───────────────────────┬──────────────────────┬──────┘
                 │ HTTP + SSE            │ direct calls         │
         ┌───────▼────────┐              │                      │
         │ web/bridge.py  │              │                      │
         └───────┬────────┘              │                      │
                 │                       │                      │
         ┌───────▼───────────────────────▼──────────────────────▼──────┐
         │  network/server.py  LedgerServerDispatcher  (RPC methods)   │
         │  network/client.py  WalletClient (signs locally, SPV)       │
         └───────────────────────────────┬─────────────────────────────┘
                                         │
         ┌───────────────────────────────▼─────────────────────────────┐
         │  ledger/chain.py  BlockchainLedger                          │
         │    chain of blocks · mempool · UTXO set · fork choice       │
         │    ├─ ledger/consensus.py   difficulty schedule, time rules │
         │    ├─ ledger/validator.py   Genesis → tip validation        │
         │    ├─ ledger/pow.py         nonce search                    │
         │    ├─ ledger/merkle.py      Merkle tree + proofs            │
         │    ├─ ledger/utxo.py        unspent-output hash map         │
         │    └─ ledger/persistence.py sealed .bclt file               │
         └───────────────────────────────┬─────────────────────────────┘
                                         │
         ┌───────────────────────────────▼─────────────────────────────┐
         │  models/  Transaction, TxInput, TxOutput, Block, BlockHeader│
         │  wallet/  Wallet (keys, coin selection, signing)            │
         │  crypto/  SHA-256, number theory, RSA                       │
         │  serialization.py  ByteBuffer (canonical big-endian bytes)  │
         └─────────────────────────────────────────────────────────────┘
```

The project is organised into three "worklets" plus integration:

- **Worklet 1 — Cryptography & transactions:** number theory, RSA, wallets, signed transactions.
- **Worklet 2 — Blocks & hashing:** SHA-256, Merkle trees, block headers, Proof-of-Work.
- **Worklet 3 — Ledger:** UTXO set, full-chain validation, fork resolution, persistence, benchmarks.
- **Integration:** TCP client/server, terminal, demo, and now the web bridge.

---

## 3. The building blocks, one idea at a time

Each idea below has three parts: **what it is**, **how this project does it**, and **where the code is**.

### 3.1 Canonical bytes

**What:** Two computers must turn the same transaction into exactly the same bytes, or their hashes will not match.

**How:** Every object is written with `ByteBuffer` in a fixed order, big-endian, with explicit lengths (`uint8`, `uint32`, `uint64`, 32-byte hashes, length-prefixed byte strings, big integers). Reading back must consume every byte; leftover bytes are an error.

**Where:** `blockchain_lite/serialization.py`.

### 3.2 Hashing (SHA-256)

**What:** A hash turns any input into a 32-byte fingerprint. Change one input bit and about half of the output bits flip (the *avalanche effect*), so you cannot change data without changing its fingerprint.

**How:** `BitLevelSHA256` implements the standard step by step: padding, 64-word message schedule, 64 compression rounds using 32-bit rotations, `Ch`, `Maj`, `Σ0`, `Σ1`. It can also record each round's state and measure avalanche (`analyze_avalanche`). `HashlibSHA256` is the optional fast backend with identical output.

**Where:** `crypto/hashing.py`, `crypto/fast_hash.py`.

### 3.3 Keys, addresses and signatures (RSA)

**What:** A wallet owns a private key (secret) and a public key (shared). Only the private key can sign; anyone can check the signature with the public key.

**How:**
1. Pick two large random primes `p` and `q`. Primality uses 40 rounds of **Miller–Rabin** after trial division.
2. `n = p·q`, `e = 65537`, `d = e⁻¹ mod λ(n)` via the extended Euclidean algorithm.
3. **Address** = `SHA-256(public key bytes)`, 32 bytes.
4. **Signing:** hash a domain tag + public key + the transaction's signing bytes, wrap it as `0x01 ‖ digest ‖ 0xBC`, and raise it to `d mod n`. Verification raises the signature to `e mod n` and compares.

Demo keys are 384 bits so wallets generate quickly in class. That is far too small for real money (see §13).

**Where:** `crypto/number_theory.py`, `crypto/asymmetric.py`, `wallet/wallet.py`.

### 3.4 Transactions and the UTXO model

**What:** Coins are not stored as "Alice: 500". Instead, every transaction creates **outputs** ("10 coins to address X"). An output that has not been spent yet is a **UTXO** (unspent transaction output). Your balance is the sum of the UTXOs that belong to you.

**How:**
- A **transfer** has inputs and outputs. Each input points at an earlier output by `(tx_id, output_index)` and carries the owner's public key and signature.
- Inputs must add up to at least the outputs. The difference is the **fee**, which goes to the miner.
- If the inputs are worth more than you want to send, the wallet adds a **change** output back to you.
- A **coinbase** transaction has no inputs. It is the miner's reward (`block_reward + fees`) and is always transaction 0 of a block. Its timestamp field stores the block height so every coinbase has a unique `tx_id`.
- `tx_id = SHA-256(full transaction bytes)`.

**Where:** `models/transaction.py`, `wallet/wallet.py` (`create_signed_transfer`: sorts UTXOs, selects enough, adds change, signs).

### 3.5 The UTXO set (a hash map)

**What:** The ledger needs to answer "is this output still unspent, and who owns it?" instantly.

**How:** `UTXOSet` is a dictionary `(tx_id, output_index) → UTXOEntry(amount, owner, block, is_coinbase)`. Applying a block works on a **clone** first; only if every transaction is valid does the clone replace the real set. So a bad block can never leave the set half-updated.

**Where:** `ledger/utxo.py`.

### 3.6 The mempool

**What:** The waiting room for valid transactions that are not in a block yet.

**How:** `submit_transaction` checks the transaction against the confirmed UTXOs **and** against outputs already claimed by other pending transactions (so you cannot double-spend inside the mempool), checks signatures and ownership, checks the fee, then stores it. Duplicates are ignored; the mempool has a size cap.

**Where:** `ledger/chain.py` (`submit_transaction_object`).

### 3.7 The Merkle tree

**What:** One 32-byte value (the **Merkle root**) that commits to every transaction in a block. If any transaction changes, the root changes.

**How:**
- **Leaf** = `H(0x00 ‖ tx_id)`. **Parent** = `H(0x01 ‖ left ‖ right)`. The different prefixes stop anyone passing a leaf off as an inner node.
- If a level has an odd number of nodes, the last one is paired with itself.
- A **Merkle proof** for one transaction is the list of sibling hashes on the path to the root: `log₂(N)` hashes. With 9 transactions, that is 4 hashes. A light client can check a transaction is in a block without downloading the block. The verifier also checks left/right positions and blocks the "odd-tail" spoofing trick.

**Where:** `ledger/merkle.py`.

### 3.8 The block and its 88-byte header

**What:** A block is a header plus a list of transactions.

**How:** The header is exactly 88 bytes:

| Field | Size | Meaning |
| :--- | ---: | :--- |
| `index` | 4 B | height of the block (Genesis = 0) |
| `previous_hash` | 32 B | hash of the block before it — this is the "chain" |
| `merkle_root` | 32 B | commits to all the transactions |
| `timestamp` | 8 B | seconds since 1970 |
| `difficulty` | 4 B | how many leading zero bits the hash needs |
| `nonce` | 8 B | the number the miner keeps changing |

**Block hash** = `SHA-256(header)`. Only the header is hashed, but because it contains the Merkle root, the hash still depends on every transaction.

**Where:** `models/block.py`.

### 3.9 Proof-of-Work

**What:** Making a block must cost real computing effort, so rewriting history is expensive.

**How:** The miner tries `nonce = 0, 1, 2, …`, hashing the header each time, until the hash as a number is below `2^(256 − D)`, which means its first `D` bits are zero. Each try succeeds with probability `2^−D`, so on average a block needs `2^D` tries. Difficulty 4 needs about 16 tries; difficulty 20 needs about a million.

**Where:** `ledger/pow.py` (`ProofOfWorkMiner.mine_block_with_stats`).

### 3.10 Validation from Genesis to tip

**What:** Anyone can check a whole chain without trusting whoever sent it.

**How:** `FullChainValidator` walks from block 0 and checks, for every block: index order, `previous_hash` link, header hash, Proof-of-Work, the difficulty the schedule requires, timestamps, the Merkle root recomputed from the transactions, every signature and ownership check, no double spends, and that the coinbase does not pay more than reward + fees. It rebuilds the UTXO set as it goes. Genesis can be pinned to a known hash (a "trust anchor").

**Where:** `ledger/validator.py`, `ledger/consensus.py`.

### 3.11 Forks: most cumulative work wins

**What:** If two valid versions of the chain exist, which one is real?

**How:** Each candidate is fully validated first; invalid chains lose no matter how long they are. Among valid ones, the winner is the chain with the most **cumulative work**, `Σ 2^difficulty`. On a tie, the current chain stays.

**Where:** `ledger/chain.py` (`resolve_forks`).

### 3.12 Saving to disk

**What:** The chain survives a restart, and a tampered file is detected.

**How:** The `.bclt` file is `"BCLT" + version + header values + every block + a SHA-256 seal over everything`. Saving writes a temporary file, `fsync`s it and atomically renames it, so a crash mid-write cannot corrupt the old file. Loading checks the seal **and** re-validates the whole chain.

**Where:** `ledger/persistence.py`.

### 3.13 Client and server

**What:** The wallet (client) and the ledger (server) are separate programs, like a real wallet app talking to a node.

**How:** Messages are `[4-byte length][JSON]` over TCP on `127.0.0.1`. The client signs locally and sends only signed bytes; any parameter containing `private_key` is rejected. Mining over RPC needs a token. The client can also act as an **SPV light client**: it downloads 88-byte headers, checks links, Proof-of-Work and the difficulty schedule from a trusted Genesis, then verifies Merkle proofs against those headers.

**Where:** `network/transport.py`, `network/server.py`, `network/client.py`. Method list: [`RPC_Reference.md`](RPC_Reference.md).

---

## 4. The life of a transaction

Example: **Alice sends 8 coins to Bob with a 1-coin fee.**

1. **Find Alice's coins.** `ledger.get_spendable_utxos(alice.address)` returns her unspent outputs.
2. **Pick coins and build the transaction.** `Wallet.create_signed_transfer` sorts her UTXOs by amount and picks enough to cover `8 + 1`. Say it picks one 10-coin output. Outputs: 8 → Bob, 1 → Alice (change). Fee = 10 − 9 = 1.
3. **Sign.** The wallet serializes the transaction without signatures (`signing_preimage_bytes`) and signs that with Alice's RSA private key. The signature goes into each input.
4. **Submit.** The signed bytes go to `submit_transaction` (over TCP, or through the web bridge). The ledger checks: not a coinbase, timestamp sane, inputs exist and are unspent, not already claimed in the mempool, `SHA-256(pubkey)` matches each input's owner, signatures valid, value conserved, fee ≥ minimum.
5. **Wait in the mempool** until someone mines a block.
6. **Mined.** The transaction is included in the next block (§5). Its input is removed from the UTXO set; its two outputs are added.
7. **Final.** Bob's balance now includes the 8 coins. Anyone can prove the transaction is in the block with a 4-hash Merkle proof.

---

## 5. The life of a block

What happens in `BlockchainLedger.mine_pending_transactions(miner_address)`:

1. **Collect.** Take every mempool transaction, applying each to a cloned UTXO set to confirm it still works and to add up the fees.
2. **Coinbase.** Put a coinbase at slot 0 paying the miner `50 + fees`.
3. **Merkle root.** Hash each transaction to its `tx_id`, make leaves, and hash pairs up to the root.
4. **Header.** Fill in `index`, `previous_hash` (the current tip's hash), `merkle_root`, `timestamp`, and the **difficulty the consensus schedule requires** (§6).
5. **Proof-of-Work.** Try nonces until the header hash has `D` leading zero bits. This runs outside the ledger's state lock, so balances can still be read while mining.
6. **Append.** `append_mined_block` re-checks everything under the lock: correct index, links to the tip, header and Merkle integrity, Proof-of-Work, consensus rules. Then it updates the UTXO set, removes now-spent transactions from the mempool, and indexes the block for address history.

Because block N stores the hash of block N−1, and that hash depends on N−1's Merkle root, which depends on every transaction in it, **changing anything in an old block changes its hash and breaks every link after it** (§7).

---

## 6. Difficulty retargeting

**Problem:** with a fixed difficulty, a faster computer simply makes blocks faster. A real blockchain keeps the block time steady by adjusting difficulty.

**The rule** (`ledger/consensus.py`, `expected_difficulty`):

- Every `retarget_interval` blocks (the web app uses 4), look at how long the recent blocks took.
- If they came **faster than 0.75× the target**, difficulty goes **up by 1 bit** (each block now needs twice the work).
- If they came **slower than 1.33× the target**, difficulty goes **down by 1 bit**.
- Otherwise it stays. It is always kept between `min_difficulty` and `max_difficulty` (1 and 24).
- Between retargets, every block must use the same difficulty as the block before it.

The required difficulty is **computed from history, never trusted from the block**. A block that claims any other difficulty, higher or lower, is rejected. Timestamps are bounded too (at least the median of the last 11 blocks, at most 2 hours in the future), so a miner cannot fake fast or slow blocks to steer difficulty.

**In the web app:** the bridge starts with a 10-second target. The retarget window spans `interval − 1` gaps between blocks, so the bridge scales the protocol parameter (`7.5 s` for an interval of 4) to make the real per-block thresholds **7.5 s** (faster → +1) and **13.3 s** (slower → −1). The ten pre-mined demo blocks are back-dated at an even pace, so they neither raise nor lower the difficulty; live mining decides.

**What you see:** with **Auto-mine** on, blocks come in under a second at difficulty 4, so the difficulty climbs by one bit every 4 blocks until a block takes about 10 seconds. On this machine (about 250,000 hashes per second with the fast backend) that happens around 21–22 bits. With the slow bit-level SHA-256 it settles much lower, because the same 10 seconds buys far fewer hashes. That is the point of retargeting: block time stays steady whatever the hash power.

**Who is mining?** In this project there is one node and one miner, the demo **Miner** wallet. Every block's coinbase pays that wallet. There is no race between competing miners; difficulty adjusts against the clock. Auto-mine also mines blocks with an empty mempool, which contain only the coinbase. That is why the total supply keeps rising by 50 per block while it runs.

---

## 7. How the chain defends itself

| Attack | What stops it | Where |
| :--- | :--- | :--- |
| Edit an amount in an old transaction | `tx_id` changes → Merkle root changes → block hash changes → next block's `previous_hash` no longer matches. The signature also stops verifying. | `validator.py`, `chain.trace_tamper_cascade` |
| Spend the same coins twice | UTXO set and mempool track every spent `(tx_id, index)` | `utxo.py`, `chain.py` |
| Spend someone else's coins | `SHA-256(pubkey)` must equal the output's owner, and the signature must verify | `transaction.py`, `utxo.py` |
| Pay yourself a huge reward | coinbase ≤ reward + fees, reward comes from protocol parameters | `utxo.apply_block` |
| Claim an easy difficulty | difficulty is recomputed from history and must match exactly | `consensus.py` |
| Fake timestamps | median-time-past and 2-hour future limit | `consensus.py` |
| Replace the whole chain with a longer fake | full validation first, then most cumulative work, Genesis pinned | `chain.resolve_forks` |
| Fake a Merkle proof | direction checks and the odd-tail guard | `merkle.verify_proof` |
| Edit the saved file | SHA-256 seal + full re-validation on load | `persistence.py` |
| Edit your own copy of the ledger (web app) | The copy fails its own checks, cannot vote, and is replaced by the valid majority at the next network check | `web/network.py` |
| Send a private key to the server | rejected by name; no method needs one | `network/server.py` |

`tests/test_attack_scenarios.py` replays each of these and shows it fails.

---

## 8. Where everything lives (code map)

### `blockchain_lite/` — the core package (standard library only)

| Path | What it does |
| :--- | :--- |
| `interfaces.py` | Shared constants, exception types and abstract interfaces |
| `serialization.py` | `ByteBuffer`: canonical big-endian reader/writer |
| `crypto/hashing.py` | Bit-level SHA-256, round tracer, avalanche analyzer |
| `crypto/fast_hash.py` | Optional `hashlib` backend, bit-identical |
| `crypto/number_theory.py` | Modular arithmetic, `pow_mod`, extended GCD, Miller–Rabin, prime generation |
| `crypto/asymmetric.py` | RSA keys, signing, verification, key-size warnings |
| `models/transaction.py` | `TxInput`, `TxOutput`, `Transaction`, double-spend checks |
| `models/block.py` | `Block`, `BlockHeader` (88 bytes), Merkle and header checks |
| `wallet/wallet.py` | `Wallet`: keys, address, coin selection, change, signing |
| `wallet/demo_wallets.py` | Builds the demo: 20 named wallets + Miner, Genesis + 10 pre-mined blocks of 8 transfers each |
| `ledger/merkle.py` | `MerkleTree`, proofs, proof serialization |
| `ledger/pow.py` | Nonce search, difficulty target, mining stats |
| `ledger/consensus.py` | Difficulty schedule, timestamp rules, coinbase height |
| `ledger/utxo.py` | `UTXOSet` hash map, atomic block application |
| `ledger/validator.py` | `FullChainValidator`, tamper-cascade report |
| `ledger/chain.py` | `BlockchainLedger`: mempool, mining, fork choice, queries |
| `ledger/persistence.py` | `.bclt` save/load with seal and atomic write |
| `network/transport.py` | Length-prefixed JSON framing |
| `network/server.py` | `LedgerServerDispatcher` (RPC methods), TCP server |
| `network/client.py` | `WalletClient`, SPV header verification |
| `cli/terminal.py` | Interactive terminal console (menu items 0–9) |
| `cli/demo.py` | Automated 6-stage viva demo |
| `benchmarks/pow_benchmark.py` | Difficulty vs. time statistics, hash backend comparison |

### Around the package

| Path | What it does |
| :--- | :--- |
| `web/bridge.py` | HTTP server for the browser: JSON API, live events, auto-miner, adding people (§9) |
| `web/network.py` | Everyone's ledger copy, tampering, and the periodic majority check (§9.1) |
| `web/static/` | `index.html`, `app.css`, `app.js` — the browser frontend |
| `viz/scenes.py`, `viz/render.py` | Manim scenes and the renderer (§10) |
| `run_terminal.py`, `run/terminal.py` | Launchers for the terminal console |
| `run_tests.py` | Runs every test module |
| `tools/bundle.py` | Builds `blockchain_lite_complete.py`, a single-file copy of the package |
| `tests/` | 14 test modules (§12) |
| `docs/` | This guide, the frontend guide, the protocol spec, HLD, RPC reference, viva guide |
| `Dockerfile`, `docker-compose.yml` | Container that runs the tests, then the terminal |
| `core/` | An older, separate prototype (`ledger.py`, `validation.py`). Nothing in the package or the tests uses it. |

---

## 9. The web frontend and bridge

The browser cannot talk raw TCP, so `web/bridge.py` sits in between. It is a standard-library `http.server`, kept **outside** the package so the package stays dependency-free.

```text
Browser (index.html + app.js)
   │  fetch /api/*           ◄── JSON
   │  EventSource /events    ◄── live events (Server-Sent Events)
   ▼
web/bridge.py  ── BridgeState ──► LedgerServerDispatcher ──► BlockchainLedger
                     │
                     ├── LedgerNetwork (web/network.py): one ledger copy per person,
                     │       gossip, tampering, periodic majority check
                     ├── AutoMiner (background thread)
                     └── RenderQueue (optional, Manim)
```

**API**

| Method & path | Does |
| :--- | :--- |
| `GET /api/state` | Chain info, consensus/difficulty info, every block summary, mempool, wallets with balances |
| `GET /api/block?index=N` | One block: header, transactions (with names), all Merkle levels |
| `GET /api/proof?block=N&tx=I` | Merkle proof for transaction I, whether it verifies, and which tree nodes are on the path |
| `GET /api/trace?index=N` | Everything Block Forge needs to replay block N: transactions, one hashed transaction with real avalanche bits, leaves, Merkle levels, the last ≤64 nonce attempts recomputed, UTXO changes, balances |
| `POST /api/tx` `{from, to, amount, fee}` | Sign a transfer with the demo wallet and submit it through `submit_transaction` |
| `POST /api/mine` | Mine the mempool into a block for the Miner wallet; returns its trace |
| `POST /api/tamper` `{block, tx}` | Run `trace_tamper_cascade` on a copy of the chain (the real chain is untouched) |
| `GET /api/network` | Every person's ledger copy: height, in sync or tampered, countdown to the next network check |
| `POST /api/network/tamper` `{name, block, tx, amount}` | Edit one transaction amount in one person's copy |
| `POST /api/network/audit` | Run the network check now |
| `POST /api/people` `{name, fund}` | Add a person: new RSA wallet, own ledger copy, optional coins from the Miner |
| `POST /api/autominer` `{on}` | Start or stop the background miner |
| `GET /api/renders` | List of rendered Manim videos |
| `GET /events` | Live events: `tx_submitted`, `block_mined`, `difficulty_changed`, `autominer`, `copy_tampered`, `network_audit`, `ledger_repaired`, `person_joined`, `render_ready` |

**Startup:** the bridge builds the demo chain (about 1 second with the fast hash), binds to `127.0.0.1:8080`, and serves `web/static/`.

**Flags:** `--port`, `--host`, `--bit-level-hash` (use the from-scratch SHA-256), `--rsa-bits`, `--block-time` (default 10), `--retarget-interval` (default 4; 0 = fixed difficulty), `--max-difficulty` (default 24), `--auto-mine`, `--audit-interval` (seconds between network checks, default 20), `--render`, `--render-quality`.

### 9.1 Everyone keeps a copy: tampering and repair

The core package is a single node. To show what a network of many ledger copies adds, `web/network.py` gives **every person their own copy** of the chain (demo wallets, the Miner, and anyone added on the People page):

- **Copies are cheap.** Blocks are immutable objects, so honest copies share them; a copy is just a list.
- **Gossip.** When a block is mined, every copy receives it (`LedgerNetwork.sync`).
- **Tampering.** Tamper Lab edits one transaction amount in one person's copy and leaves the block header alone, like someone editing their own file. Nobody else is affected.
- **Network check** (every 20 s, or *Check now*):
  1. Each copy is checked on its own: Merkle roots recomputed, header hashes, Proof-of-Work, `previous_hash` links. A tampered copy fails, so it cannot vote.
  2. Valid copies are grouped by exact content; the largest group is the **majority ledger**.
  3. Every copy that differs from it is replaced by it, and a `ledger_repaired` event (shown as a notification) reports it.
- **Why validity comes before the vote:** if many people held the same edited copy, they still could not out-vote the honest copies, because an edited copy fails its own checks. This mirrors the core rule for forks (§3.11): validate first, then choose.
- **Adding a person** creates a new RSA wallet, gives them the majority copy, and (optionally) sends them coins from the Miner as a normal transaction that lands in the next block.

This simulation runs inside one process; there is still no real peer-to-peer networking (§13).

**Safety:** loopback by default; static files cannot escape `web/static/`; request bodies are capped at 64 KB; bad input returns a JSON error with status 400. **Demo custody:** like the terminal console, the bridge holds the demo wallets' private keys and signs for them. That is convenient for a classroom and is *not* how a real wallet should work — in `network/client.py` the wallet signs on the client side.

---

## 10. Manim animations

[Manim](https://www.manim.community/) is the Python library 3Blue1Brown created for mathematical animations. `viz/scenes.py` uses it to turn one block's real trace into a video:

| Scene | Shows |
| :--- | :--- |
| `CollectTxScene` | Mempool transactions sliding into the block, coinbase first |
| `HashScene` | Transaction bytes entering a SHA-256 ring, 64 rounds ticking, the `tx_id` and leaf hash, the avalanche grid |
| `MerkleScene` | Leaves at the bottom, pairs merging level by level up to the root |
| `PoWScene` | The header fields, the nonce counter, failed hashes, the winning hash |
| `AppendScene` | The new block linking to the previous one through `previous_hash`, UTXO changes |
| `BlockForgeScene` | All five in a row |

`viz/render.py` writes the trace to a temporary file, runs Manim on it, and saves `web/static/renders/block_<N>.mp4`. The browser's Block Forge plays it when it exists.

Manim is optional and is **not installed** by default. It also needs system libraries (cairo, pango, ffmpeg). Install with `pip install -r viz/requirements.txt`. These scenes have not been rendered on this machine yet.

---

## 11. How to run everything

```bash
# Terminal console (bit-level SHA-256; add --fast-hash for speed)
python3 run_terminal.py
python3 run_terminal.py --fast-hash

# Automated 6-stage viva demo, status, benchmark
python3 run_terminal.py --demo
python3 run_terminal.py --status
python3 run_terminal.py --benchmark

# Browser app: open http://127.0.0.1:8080
python3 -m web.bridge
python3 -m web.bridge --auto-mine             # start mining straight away
python3 -m web.bridge --retarget-interval 0   # fixed difficulty 4
python3 -m web.bridge --render                # also render Manim videos

# Render a block by hand from a running bridge
python3 -m viz.render --block 10

# All tests
python3 run_tests.py

# Docker
docker compose run --rm terminal
docker compose --profile test run --rm test-suite
```

The **demo chain** used by the terminal and the web app: Genesis gives 20 named wallets between 300 and 500 coins (9,200 in total), then 10 blocks are pre-mined, each with 8 signed transfers plus a coinbase. The Miner wallet starts at 0 and earns every block reward. Wallet keys are random each run, so hashes differ every time you start.

---

## 12. Tests

`python3 run_tests.py` runs 122 tests across 14 modules (one is skipped):

| Module | Covers |
| :--- | :--- |
| `test_phase1_foundation` | Interfaces, constants, `ByteBuffer`, standard-library-only import audit |
| `test_phase2_worklet1` | Number theory, Miller–Rabin, RSA, transactions, wallet signing |
| `test_phase3_worklet2` | SHA-256, Merkle trees and proofs, blocks, chaining, Proof-of-Work |
| `test_phase4_worklet3` | Full validation, fork resolution, UTXO, persistence |
| `test_phase5_integration` | Client and server over in-memory and real TCP transport |
| `test_phase6_defensive_verification` | Defensive cases and regressions (categories A–G) |
| `test_phase7_advanced_features` | Difficulty retargeting, address history, advanced features |
| `test_phase9_core_engineering` | Non-blocking mining, authenticated mining RPC, incremental mempool |
| `test_phase11_fast_hash` | Fast backend is bit-identical to the from-scratch SHA-256 |
| `test_phase12_serialization_properties` | Randomised round-trip and mutation tests for serialization |
| `test_phase13_spv_and_keys` | SPV header-chain verification, RSA key-size guidance |
| `test_attack_scenarios` | Each known attack (D1–D8) replayed and shown to fail |
| `test_terminal_console` | Every terminal menu action works |
| `test_web_bridge` | Web API, live events, static files, auto-miner, difficulty going up and down, ledger copies (tamper → network check → repair), adding people |

---

## 13. Limits and honest caveats

- **Educational cryptography.** 384/512-bit RSA and a custom, non-constant-time signature scheme. Real systems use ≥ 2048-bit RSA or elliptic curves with vetted libraries.
- **One node.** There is no real peer-to-peer network or competing miners. The web app simulates everyone's ledger copy and a majority check inside one process (§9.1); fork resolution is implemented and tested in the core.
- **Demo custody in the web app and terminal.** The demo wallets' private keys live in the same process as the ledger.
- **Retargeting is gentle.** One bit per interval means climbing from 4 to 22 bits takes about 70 blocks. Bitcoin instead adjusts proportionally (up to 4× per period).
- **Python speed.** The from-scratch SHA-256 manages roughly a thousand hashes per second; the fast backend about 250k–600k. Real mining hardware does trillions.
- **Manim renders are untested** on this machine (Manim is not installed).
- **Python version.** The project targets Python 3.11+; this machine has 3.9.6, and the code and tests run there too.
- `SECURITY.md` currently holds only a placeholder line; the threat model is summarised in [`HLD_and_Interfaces.md`](HLD_and_Interfaces.md) §6 and in this section.

---

## 14. Glossary

| Term | Meaning |
| :--- | :--- |
| **Address** | `SHA-256` of a wallet's public key; where coins are sent |
| **Avalanche effect** | One changed input bit flips about half the hash's output bits |
| **Block height / index** | Position in the chain; Genesis is 0 |
| **Coinbase** | Transaction 0 of a block; creates the miner's reward from nothing |
| **Cumulative work** | `Σ 2^difficulty` over a chain; decides forks |
| **Difficulty (D)** | Required number of leading zero bits in a block hash; expected work `2^D` |
| **Fee** | Inputs minus outputs of a transfer; paid to the miner |
| **Genesis** | Block 0; creates the starting balances |
| **Mempool** | Valid transactions waiting to be mined |
| **Merkle root / proof** | One hash committing to all transactions / the sibling hashes proving one is included |
| **Nonce** | The number the miner changes to search for a valid hash |
| **Retargeting** | Adjusting difficulty to keep block time near a target |
| **SPV** | Simplified Payment Verification: checking inclusion with headers + Merkle proofs only |
| **SSE** | Server-Sent Events: a one-way live stream from server to browser |
| **Tip** | The latest block |
| **UTXO** | Unspent transaction output: a coin that can still be spent |
