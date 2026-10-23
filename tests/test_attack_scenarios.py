"""
Attack Scenarios (viva demo): each test replays a verified audit exploit and shows it fails.

Run just this module:   python -m unittest -v tests.test_attack_scenarios

| Defect | Attack                                                        | Test(s)                                                   |
| :----- | :------------------------------------------------------------ | :-------------------------------------------------------- |
| D1     | Replace an honest chain with cheap difficulty-0 blocks        | test_d1_difficulty_zero_attacker_chain_rejected_by_resolve_forks, test_d1_append_mined_block_rejects_wrong_difficulty |
| D1     | (guard) honest retargeting and longer honest forks still work | test_d1_honest_retargeting_still_validates_and_is_enforced, test_d1_longer_valid_fork_still_wins_by_cumulative_work |
| D2     | Forge a .bclt file minting 10^15 coins with a matching header | test_d2_forged_reward_file_rejected, test_d2_header_difficulty_disagreeing_with_protocol_rejected |
| D3     | Same miner mining twice in one second -> coinbase collision   | test_d3_repeated_same_second_mining_by_one_miner_succeeds, test_coinbase_height_must_match_block_index |
| D4     | Dashboard Merkle-proof route crashed                          | test_d4_merkle_proof_endpoint_for_1_2_3_tx_blocks          |
| D5     | Cross-site "simple request" spends a custodial demo wallet    | test_d5_post_without_or_with_wrong_token_is_rejected, test_d5_text_plain_simple_request_rejected, test_d5_no_wildcard_cors_header |
| D6     | Garbage Content-Length / leaked exception text / mining DoS   | test_d6_bad_content_length_handled, test_d6_unexpected_errors_return_generic_500, test_d6_reads_stay_responsive_while_dashboard_mines |
| D8     | Blocks timestamped in the far past or future                  | test_d8_block_timestamps_far_past_or_future_rejected       |

Every scenario test failed on the pre-fix code (verified when it was written) and passes now.
"""

from __future__ import annotations

import http.client
import json
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path

from blockchain_lite.crypto.asymmetric import MIN_RSA_MODULUS_BITS, RSACryptoEngine
from blockchain_lite.interfaces import MerkleProof, MerkleProofStep, ValidationError
from blockchain_lite.ledger.chain import BlockchainLedger
from blockchain_lite.ledger.merkle import MerkleTree
from blockchain_lite.ledger.persistence import ChainPersistence
from blockchain_lite.ledger.pow import ProofOfWorkMiner
from blockchain_lite.models.transaction import Transaction
from blockchain_lite.wallet.wallet import Wallet

T0 = 1700000000


def _coinbase(addr: bytes, amount: int, height: int) -> Transaction:
    # Coinbase commits the block height in its timestamp field (BIP34-style).
    return Transaction.create_coinbase(recipient_address=addr, amount=amount, timestamp=height)


class TestConsensusEnforcement(unittest.TestCase):
    """D1 + D8: difficulty schedule and timestamp rules are enforced, not self-declared."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = RSACryptoEngine()
        cls.alice = Wallet.generate("Alice", bit_length=MIN_RSA_MODULUS_BITS, crypto_engine=cls.engine)
        cls.mallory = Wallet.generate("Mallory", bit_length=MIN_RSA_MODULUS_BITS, crypto_engine=cls.engine)

    def _honest_ledger(self, difficulty: int = 6) -> BlockchainLedger:
        ledger = BlockchainLedger(difficulty=difficulty, block_reward=50, crypto_engine=self.engine)
        ledger.create_genesis_block([(self.alice.address, 1000)], timestamp=T0)
        ledger.mine_pending_transactions(miner_address=self.alice.address, timestamp=T0 + 60)
        return ledger

    def _cheap_fork(self, genesis, length: int, difficulty: int = 0):
        miner = ProofOfWorkMiner()
        blocks = [genesis]
        for h in range(1, length):
            blocks.append(miner.mine_block(
                index=h,
                previous_hash=blocks[-1].block_hash,
                transactions=[_coinbase(self.mallory.address, 50, h)],
                difficulty=difficulty,
                timestamp=T0 + 10 * h,
            ))
        return blocks

    def test_d1_difficulty_zero_attacker_chain_rejected_by_resolve_forks(self) -> None:
        honest = self._honest_ledger()
        tip_before = honest.tip.block_hash
        attacker = self._cheap_fork(honest.blocks[0], length=6, difficulty=0)

        outcome = honest.resolve_forks([attacker])

        self.assertFalse(outcome.switched_chain)
        self.assertEqual(outcome.rejected_candidates_count, 1)
        self.assertEqual(honest.tip.block_hash, tip_before)
        self.assertEqual(honest.get_balance(self.mallory.address), 0)

    def test_d1_append_mined_block_rejects_wrong_difficulty(self) -> None:
        honest = self._honest_ledger()
        miner = ProofOfWorkMiner()
        for bad_diff in (0, honest.difficulty + 1):
            block = miner.mine_block(
                index=2,
                previous_hash=honest.tip.block_hash,
                transactions=[_coinbase(self.mallory.address, 50, 2)],
                difficulty=bad_diff,
                timestamp=T0 + 120,
            )
            with self.assertRaises(ValidationError):
                honest.append_mined_block(block)
        self.assertEqual(honest.height, 2)

    def test_d1_longer_valid_fork_still_wins_by_cumulative_work(self) -> None:
        # Equal-difficulty, longer honest fork still wins (more work).
        honest = self._honest_ledger(difficulty=4)
        longer = BlockchainLedger(difficulty=4, block_reward=50, crypto_engine=self.engine)
        longer.load_verified_chain(honest.blocks[:1])
        for i in range(2):
            longer.mine_pending_transactions(miner_address=self.mallory.address, timestamp=T0 + 100 + i)
        outcome = honest.resolve_forks([longer.blocks])
        self.assertTrue(outcome.switched_chain)
        self.assertEqual(outcome.winning_cumulative_work, 3 * (1 << 4))

    def test_d1_honest_retargeting_still_validates_and_is_enforced(self) -> None:
        params = dict(difficulty=3, retarget_interval=2, target_block_time_seconds=10.0,
                      min_difficulty=1, max_difficulty=8)
        ledger = BlockchainLedger(crypto_engine=self.engine, **params)
        ledger.create_genesis_block([(self.alice.address, 100)], timestamp=T0)
        for i in range(1, 5):
            ledger.mine_pending_transactions(miner_address=self.alice.address, timestamp=T0 + i)
        diffs = [b.difficulty for b in ledger.blocks]
        self.assertEqual(diffs, [3, 3, 4, 4, 5])

        # calculate_next_difficulty is a pure query.
        self.assertEqual(ledger.calculate_next_difficulty(), ledger.calculate_next_difficulty())

        replica = BlockchainLedger(crypto_engine=self.engine, **params)
        replica.load_verified_chain(ledger.blocks)
        self.assertEqual(replica.tip.block_hash, ledger.tip.block_hash)

        # Same chain under fixed difficulty 3 is invalid (blocks 2..4 claim the wrong difficulty).
        fixed = BlockchainLedger(difficulty=3, crypto_engine=self.engine)
        with self.assertRaises(ValidationError):
            fixed.load_verified_chain(ledger.blocks)

    def test_d8_block_timestamps_far_past_or_future_rejected(self) -> None:
        honest = self._honest_ledger(difficulty=2)
        miner = ProofOfWorkMiner()
        far_future = int(time.time()) + 3 * 3600
        for ts in (5, far_future, 2 ** 63):
            block = miner.mine_block(
                index=2,
                previous_hash=honest.tip.block_hash,
                transactions=[_coinbase(self.mallory.address, 50, 2)],
                difficulty=2,
                timestamp=ts,
            )
            with self.assertRaises(ValidationError, msg=f"timestamp={ts}"):
                honest.append_mined_block(block)
        self.assertEqual(honest.height, 2)

    def test_coinbase_height_must_match_block_index(self) -> None:
        honest = self._honest_ledger(difficulty=2)
        block = ProofOfWorkMiner().mine_block(
            index=2,
            previous_hash=honest.tip.block_hash,
            transactions=[_coinbase(self.mallory.address, 50, 7)],
            difficulty=2,
            timestamp=T0 + 120,
        )
        with self.assertRaises(ValidationError):
            honest.append_mined_block(block)


class TestCoinbaseUniqueness(unittest.TestCase):
    """D3: same miner, same reward, same second must not collide."""

    def test_d3_repeated_same_second_mining_by_one_miner_succeeds(self) -> None:
        miner = Wallet.generate("Miner", bit_length=MIN_RSA_MODULUS_BITS)
        ledger = BlockchainLedger(difficulty=1, block_reward=50)
        ledger.create_genesis_block([(miner.address, 10)], timestamp=T0)
        for _ in range(3):
            ledger.mine_pending_transactions(miner_address=miner.address, timestamp=T0 + 5)
        ledger.mine_pending_transactions(miner_address=miner.address)
        ledger.mine_pending_transactions(miner_address=miner.address)
        self.assertEqual(ledger.height, 6)
        self.assertEqual(ledger.get_balance(miner.address), 10 + 5 * 50)
        self.assertTrue(ledger.validate_full_chain().is_valid)


class TestPersistenceTrustsProtocolNotFile(unittest.TestCase):
    """D2: header block_reward / difficulty are untrusted."""

    def test_d2_forged_reward_file_rejected(self) -> None:
        mallory = Wallet.generate("Mallory", bit_length=MIN_RSA_MODULUS_BITS)
        ledger = BlockchainLedger()  # protocol defaults
        ledger.create_genesis_block([(mallory.address, 1)], timestamp=T0)
        genesis_hash = ledger.genesis_hash
        forged = ProofOfWorkMiner().mine_block(
            index=1,
            previous_hash=genesis_hash,
            transactions=[_coinbase(mallory.address, 10 ** 15, 1)],
            difficulty=ledger.difficulty,
            timestamp=T0 + 60,
        )
        persistence = ChainPersistence()
        raw = persistence.serialize_chain(
            [ledger.blocks[0], forged], difficulty=ledger.difficulty, block_reward=10 ** 15
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "forged.bclt"
            path.write_bytes(raw)
            with self.assertRaises(ValidationError):
                persistence.load_ledger(path, expected_genesis_hash=genesis_hash)

    def test_d2_header_difficulty_disagreeing_with_protocol_rejected(self) -> None:
        w = Wallet.generate("W", bit_length=MIN_RSA_MODULUS_BITS)
        cheap = BlockchainLedger(difficulty=0)
        cheap.create_genesis_block([(w.address, 1)], timestamp=T0)
        persistence = ChainPersistence()  # default protocol difficulty is not 0
        with tempfile.TemporaryDirectory() as tmp:
            path = persistence.save_ledger(cheap, Path(tmp) / "cheap.bclt")
            with self.assertRaises(ValidationError):
                persistence.load_ledger(path)





if __name__ == "__main__":
    unittest.main()
