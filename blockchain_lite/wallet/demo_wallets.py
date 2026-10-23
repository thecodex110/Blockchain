"""
Demo Ledger & Wallets Factory (`blockchain_lite/wallet/demo_wallets.py`).

Provides deterministic initialization of a demo ledger pre-funded with
20 named wallets + 1 miner for interactive terminal exploration, testing,
and demonstrations.

Pre-mined chain:
  - Block  #0  Genesis  (21 initial allocations)
  - Blocks #1–#10  10 mined blocks  ×  8 transfers each  = 80 transfer txs
"""

from __future__ import annotations

import time
from typing import Dict, Tuple

from blockchain_lite.crypto.hashing import default_hasher
from blockchain_lite.interfaces import HashInterface
from blockchain_lite.ledger.chain import BlockchainLedger
from blockchain_lite.wallet.wallet import Wallet


def create_demo_ledger_and_wallets(
    hasher: HashInterface = default_hasher,
    rsa_bits: int = 384,
    retarget_interval: int = 0,
    target_block_time: float = 10.0,
    max_difficulty: int = 24,
) -> Tuple[BlockchainLedger, Dict[str, Wallet]]:
    """
    Initialize an educational demo blockchain with 20 participant wallets
    plus a Miner wallet (21 total), and a rich 10-block pre-mined chain
    containing 80 signed transfer transactions across all participants.

    Genesis balances
    ----------------
    Alice 500  Bob 500  Charlie 500  Dave 500  Eve 500
    Frank 500  Grace 500  Heidi 500  Ivan 500  Judy 500
    Karl 450  Lisa 450  Mallory 400  Nina 400  Oscar 380
    Priya 360  Quinn 340  Rachel 320  Sam 300  Tina 300
    Miner 0  (earns block rewards from the 10 pre-mined blocks)

    With `retarget_interval > 0` the difficulty retargets every that many blocks
    toward `target_block_time`, and the pre-mined blocks are back-dated at an
    even pace that neither raises nor lowers the difficulty: live mining decides that.
    """
    ledger = BlockchainLedger(
        difficulty=4,
        block_reward=50,
        hasher=hasher,
        retarget_interval=retarget_interval,
        target_block_time_seconds=target_block_time,
        max_difficulty=max_difficulty,
    )

    # --- Generate all 20 participant wallets + miner ---
    alice   = Wallet.generate(label="Alice",   bit_length=rsa_bits)
    bob     = Wallet.generate(label="Bob",     bit_length=rsa_bits)
    charlie = Wallet.generate(label="Charlie", bit_length=rsa_bits)
    dave    = Wallet.generate(label="Dave",    bit_length=rsa_bits)
    eve     = Wallet.generate(label="Eve",     bit_length=rsa_bits)
    frank   = Wallet.generate(label="Frank",   bit_length=rsa_bits)
    grace   = Wallet.generate(label="Grace",   bit_length=rsa_bits)
    heidi   = Wallet.generate(label="Heidi",   bit_length=rsa_bits)
    ivan    = Wallet.generate(label="Ivan",    bit_length=rsa_bits)
    judy    = Wallet.generate(label="Judy",    bit_length=rsa_bits)
    karl    = Wallet.generate(label="Karl",    bit_length=rsa_bits)
    lisa    = Wallet.generate(label="Lisa",    bit_length=rsa_bits)
    mallory = Wallet.generate(label="Mallory", bit_length=rsa_bits)
    nina    = Wallet.generate(label="Nina",    bit_length=rsa_bits)
    oscar   = Wallet.generate(label="Oscar",   bit_length=rsa_bits)
    priya   = Wallet.generate(label="Priya",   bit_length=rsa_bits)
    quinn   = Wallet.generate(label="Quinn",   bit_length=rsa_bits)
    rachel  = Wallet.generate(label="Rachel",  bit_length=rsa_bits)
    sam     = Wallet.generate(label="Sam",     bit_length=rsa_bits)
    tina    = Wallet.generate(label="Tina",    bit_length=rsa_bits)
    miner   = Wallet.generate(label="Miner",   bit_length=rsa_bits)

    now = int(time.time())
    paced = retarget_interval > 0
    # The retarget window spans `interval - 1` block gaps (consensus.expected_difficulty),
    # so a neutral history spaces blocks interval/(interval-1) target times apart.
    spacing = target_block_time * retarget_interval / max(1, retarget_interval - 1)
    step = max(1, int(round(spacing)))
    genesis_ts = now - 11 * step if paced else now - 1200
    mined = 0

    def _mine() -> None:
        nonlocal mined
        mined += 1
        ledger.mine_pending_transactions(
            miner_address=miner.address,
            timestamp=genesis_ts + mined * step if paced else None,
        )

    # ------------------------------------------------------------------
    # Block #0  –  Genesis  (20 initial allocations)
    # ------------------------------------------------------------------
    ledger.create_genesis_block(
        initial_allocations=[
            (alice.address,   500),
            (bob.address,     500),
            (charlie.address, 500),
            (dave.address,    500),
            (eve.address,     500),
            (frank.address,   500),
            (grace.address,   500),
            (heidi.address,   500),
            (ivan.address,    500),
            (judy.address,    500),
            (karl.address,    450),
            (lisa.address,    450),
            (mallory.address, 400),
            (nina.address,    400),
            (oscar.address,   380),
            (priya.address,   360),
            (quinn.address,   340),
            (rachel.address,  320),
            (sam.address,     300),
            (tina.address,    300),
        ],
        timestamp=genesis_ts,
    )

    # Helper: single-UTXO transfer shortcut
    def _tx(sender: Wallet, recipient: Wallet, amount: int, fee: int = 1):
        return sender.create_signed_transfer(
            recipient_address=recipient.address,
            amount=amount,
            spendable_utxos=ledger.get_spendable_utxos(sender.address),
            fee=fee,
        )

    # ------------------------------------------------------------------
    # Block #1  –  8 txs  (odd-index → even-index)
    # ------------------------------------------------------------------
    ledger.submit_transaction(_tx(alice,   bob,     15))
    ledger.submit_transaction(_tx(charlie, dave,    15))
    ledger.submit_transaction(_tx(eve,     frank,   15))
    ledger.submit_transaction(_tx(grace,   heidi,   15))
    ledger.submit_transaction(_tx(ivan,    judy,    15))
    ledger.submit_transaction(_tx(karl,    lisa,    15))
    ledger.submit_transaction(_tx(mallory, nina,    15))
    ledger.submit_transaction(_tx(oscar,   priya,   15))
    _mine()

    # ------------------------------------------------------------------
    # Block #2  –  8 txs  (even-index → odd-index)
    # ------------------------------------------------------------------
    ledger.submit_transaction(_tx(bob,   charlie,  12))
    ledger.submit_transaction(_tx(dave,  eve,      12))
    ledger.submit_transaction(_tx(frank, grace,    12))
    ledger.submit_transaction(_tx(heidi, ivan,     12))
    ledger.submit_transaction(_tx(judy,  karl,     12))
    ledger.submit_transaction(_tx(lisa,  mallory,  12))
    ledger.submit_transaction(_tx(nina,  oscar,    12))
    ledger.submit_transaction(_tx(priya, quinn,    12))
    _mine()

    # ------------------------------------------------------------------
    # Block #3  –  8 txs  (lower half cycle + Quinn/Rachel/Sam/Tina debut)
    # ------------------------------------------------------------------
    ledger.submit_transaction(_tx(quinn,   rachel,  10))
    ledger.submit_transaction(_tx(rachel,  sam,      8))
    ledger.submit_transaction(_tx(sam,     tina,     7))
    ledger.submit_transaction(_tx(tina,    alice,    5))
    ledger.submit_transaction(_tx(alice,   eve,     12))
    ledger.submit_transaction(_tx(bob,     frank,   10))
    ledger.submit_transaction(_tx(charlie, grace,   10))
    ledger.submit_transaction(_tx(dave,    heidi,   10))
    _mine()

    # ------------------------------------------------------------------
    # Block #4  –  8 txs  (middle wallets rotate)
    # ------------------------------------------------------------------
    ledger.submit_transaction(_tx(eve,     ivan,    10))
    ledger.submit_transaction(_tx(frank,   judy,    10))
    ledger.submit_transaction(_tx(grace,   karl,    10))
    ledger.submit_transaction(_tx(heidi,   lisa,    10))
    ledger.submit_transaction(_tx(ivan,    mallory, 10))
    ledger.submit_transaction(_tx(judy,    nina,    10))
    ledger.submit_transaction(_tx(karl,    oscar,   10))
    ledger.submit_transaction(_tx(lisa,    priya,   10))
    _mine()

    # ------------------------------------------------------------------
    # Block #5  –  8 txs  (tail wallets + cross-group)
    # ------------------------------------------------------------------
    ledger.submit_transaction(_tx(mallory, quinn,    8))
    ledger.submit_transaction(_tx(nina,    rachel,   8))
    ledger.submit_transaction(_tx(oscar,   sam,      8))
    ledger.submit_transaction(_tx(priya,   tina,     7))
    ledger.submit_transaction(_tx(quinn,   alice,    8))
    ledger.submit_transaction(_tx(rachel,  bob,      7))
    ledger.submit_transaction(_tx(sam,     charlie,  6))
    ledger.submit_transaction(_tx(tina,    dave,     6))
    _mine()

    # ------------------------------------------------------------------
    # Block #6  –  8 txs  (skip-1 rotation across all 20)
    # ------------------------------------------------------------------
    ledger.submit_transaction(_tx(alice,   frank,   12))
    ledger.submit_transaction(_tx(bob,     grace,   12))
    ledger.submit_transaction(_tx(charlie, heidi,   12))
    ledger.submit_transaction(_tx(dave,    ivan,    12))
    ledger.submit_transaction(_tx(eve,     judy,    12))
    ledger.submit_transaction(_tx(frank,   karl,    12))
    ledger.submit_transaction(_tx(grace,   lisa,    12))
    ledger.submit_transaction(_tx(heidi,   mallory, 12))
    _mine()

    # ------------------------------------------------------------------
    # Block #7  –  8 txs  (mid-group forward)
    # ------------------------------------------------------------------
    ledger.submit_transaction(_tx(ivan,    nina,    10))
    ledger.submit_transaction(_tx(judy,    oscar,   10))
    ledger.submit_transaction(_tx(karl,    priya,   10))
    ledger.submit_transaction(_tx(lisa,    quinn,   10))
    ledger.submit_transaction(_tx(mallory, rachel,  10))
    ledger.submit_transaction(_tx(nina,    sam,     10))
    ledger.submit_transaction(_tx(oscar,   tina,     8))
    ledger.submit_transaction(_tx(priya,   alice,   10))
    _mine()

    # ------------------------------------------------------------------
    # Block #8  –  8 txs  (reverse cross-links)
    # ------------------------------------------------------------------
    ledger.submit_transaction(_tx(quinn,   bob,      8))
    ledger.submit_transaction(_tx(rachel,  charlie,  8))
    ledger.submit_transaction(_tx(sam,     dave,     8))
    ledger.submit_transaction(_tx(tina,    eve,      6))
    ledger.submit_transaction(_tx(alice,   grace,   12))
    ledger.submit_transaction(_tx(bob,     heidi,   12))
    ledger.submit_transaction(_tx(charlie, ivan,    12))
    ledger.submit_transaction(_tx(dave,    judy,    12))
    _mine()

    # ------------------------------------------------------------------
    # Block #9  –  8 txs  (lower group cycle)
    # ------------------------------------------------------------------
    ledger.submit_transaction(_tx(eve,     karl,    10))
    ledger.submit_transaction(_tx(frank,   lisa,    10))
    ledger.submit_transaction(_tx(grace,   mallory, 10))
    ledger.submit_transaction(_tx(heidi,   nina,    10))
    ledger.submit_transaction(_tx(ivan,    oscar,   10))
    ledger.submit_transaction(_tx(judy,    priya,   10))
    ledger.submit_transaction(_tx(karl,    quinn,   10))
    ledger.submit_transaction(_tx(lisa,    rachel,  10))
    _mine()

    # ------------------------------------------------------------------
    # Block #10  –  8 txs  (wrap-up cross-send)
    # ------------------------------------------------------------------
    ledger.submit_transaction(_tx(mallory, sam,      8))
    ledger.submit_transaction(_tx(nina,    tina,     8))
    ledger.submit_transaction(_tx(oscar,   alice,   10))
    ledger.submit_transaction(_tx(priya,   bob,     10))
    ledger.submit_transaction(_tx(quinn,   charlie, 10))
    ledger.submit_transaction(_tx(rachel,  dave,     8))
    ledger.submit_transaction(_tx(sam,     eve,      8))
    ledger.submit_transaction(_tx(tina,    frank,    5))
    _mine()

    wallets: Dict[str, Wallet] = {
        "Alice":   alice,
        "Bob":     bob,
        "Charlie": charlie,
        "Dave":    dave,
        "Eve":     eve,
        "Frank":   frank,
        "Grace":   grace,
        "Heidi":   heidi,
        "Ivan":    ivan,
        "Judy":    judy,
        "Karl":    karl,
        "Lisa":    lisa,
        "Mallory": mallory,
        "Nina":    nina,
        "Oscar":   oscar,
        "Priya":   priya,
        "Quinn":   quinn,
        "Rachel":  rachel,
        "Sam":     sam,
        "Tina":    tina,
        "Miner":   miner,
    }
    return ledger, wallets
