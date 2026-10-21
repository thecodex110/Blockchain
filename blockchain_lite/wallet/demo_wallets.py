"""
Demo Ledger & Wallets Factory (`blockchain_lite/wallet/demo_wallets.py`).

Provides deterministic initialization of a demo ledger pre-funded with
named wallets (Alice, Bob, Charlie, Miner) for interactive terminal exploration,
testing, and demonstrations.
"""

from __future__ import annotations

import time
from typing import Dict, Tuple

from blockchain_lite.crypto.hashing import default_hasher
from blockchain_lite.interfaces import HashInterface
from blockchain_lite.ledger.chain import BlockchainLedger
from blockchain_lite.wallet.wallet import Wallet


def create_demo_ledger_and_wallets(
    hasher: HashInterface = default_hasher, rsa_bits: int = 384
) -> Tuple[BlockchainLedger, Dict[str, Wallet]]:
    """
    Initialize an educational demo blockchain pre-allocated with Alice, Bob,
    Charlie, and Miner wallets, with a mined Block #1 for immediate inspection.
    """
    ledger = BlockchainLedger(difficulty=4, block_reward=50, hasher=hasher)

    alice = Wallet.generate(label="Alice", bit_length=rsa_bits)
    bob = Wallet.generate(label="Bob", bit_length=rsa_bits)
    charlie = Wallet.generate(label="Charlie", bit_length=rsa_bits)
    miner = Wallet.generate(label="Miner", bit_length=rsa_bits)

    ledger.create_genesis_block(
        initial_allocations=[
            (alice.address, 100),
            (bob.address, 50),
            (charlie.address, 25),
        ],
        timestamp=int(time.time()) - 300,
    )

    # Pre-mine Block #1 with a sample transfer for initial demonstration
    alice_utxos = ledger.get_spendable_utxos(alice.address)
    tx1 = alice.create_signed_transfer(
        recipient_address=bob.address,
        amount=20,
        spendable_utxos=alice_utxos,
        fee=2,
    )
    ledger.submit_transaction(tx1)
    ledger.mine_pending_transactions(miner_address=miner.address)

    wallets = {
        "Alice": alice,
        "Bob": bob,
        "Charlie": charlie,
        "Miner": miner,
    }
    return ledger, wallets
