"""
Tests for Blockchain-Lite Terminal Console (`tests/test_terminal_console.py`).

Verifies that all blockchain functionality is completely accessible and operable
via the interactive Terminal interface:
- Chain status query
- Block exploration and detailed transaction inspection
- Digital wallet balance and UTXO accounting
- Cryptographic transfer creation, RSA signing, and mempool validation
- Proof-of-Work block mining
- Merkle tree inclusion proof (SPV) verification
- Cryptographic tamper simulation and cascade failure analysis
"""

from __future__ import annotations

import io
import unittest
from unittest.mock import patch

from blockchain_lite.cli.terminal import TerminalConsole, format_hash
from blockchain_lite.crypto.hashing import default_hasher
from blockchain_lite.interfaces import TX_TYPE_COINBASE, TX_TYPE_TRANSFER
from blockchain_lite.ledger.chain import BlockchainLedger
from blockchain_lite.wallet.demo_wallets import create_demo_ledger_and_wallets
from blockchain_lite.wallet.wallet import Wallet


class TestTerminalConsole(unittest.TestCase):
    """Test suite for TerminalConsole operations."""

    def setUp(self) -> None:
        self.ledger, self.wallets = create_demo_ledger_and_wallets(
            hasher=default_hasher, rsa_bits=384
        )
        self.console = TerminalConsole(
            ledger=self.ledger, wallets=self.wallets, hasher=default_hasher
        )

    def test_format_hash(self) -> None:
        h = bytes.fromhex("11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff")
        formatted = format_hash(h, prefix_len=4, suffix_len=4)
        self.assertEqual(formatted, "1122...eeff")

    def test_banner_and_menu(self) -> None:
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            self.console.print_banner()
            self.console.print_menu()
        output = buf.getvalue()
        self.assertIn("BLOCKCHAIN-LITE LEDGER & DIGITAL WALLET", output)
        self.assertIn("MAIN MENU", output)
        self.assertIn("Chain Status", output)
        self.assertIn("Explore Blocks", output)
        self.assertIn("Wallets & Balance", output)
        self.assertIn("Send Transfer", output)
        self.assertIn("Mine Block", output)
        self.assertIn("Verify Merkle Proof", output)
        self.assertIn("Simulate Tamper", output)

    def test_show_chain_status(self) -> None:
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            self.console.show_chain_status()
        output = buf.getvalue()
        self.assertIn("BLOCKCHAIN STATUS", output)
        self.assertIn("Height (Total Blocks)", output)
        self.assertIn("VALID [Integrity Confirmed]", output)
        self.assertIn("Mining Difficulty", output)

    def test_list_and_inspect_blocks(self) -> None:
        # Test listing blocks without inspecting
        buf = io.StringIO()
        with patch("sys.stdout", buf), patch("builtins.input", return_value=""):
            self.console.list_blocks()
        output = buf.getvalue()
        self.assertIn("BLOCKCHAIN BLOCKS", output)
        self.assertIn("#0", output)
        self.assertIn("#1", output)

        # Test inspecting block #1
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            self.console.inspect_block(1)
        output = buf.getvalue()
        self.assertIn("DETAILS FOR BLOCK #1", output)
        self.assertIn("COINBASE", output)
        self.assertIn("TRANSFER", output)

    def test_show_wallets(self) -> None:
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            self.console.show_wallets()
        output = buf.getvalue()
        self.assertIn("WALLETS & BALANCES", output)
        for name in ("Alice", "Bob", "Charlie", "Miner"):
            self.assertIn(name, output)

    def test_send_transfer_and_mine(self) -> None:
        # Alice sends 10 coins to Charlie (fee 1)
        simulated_inputs = iter(["Alice", "Charlie", "10", "1"])
        buf = io.StringIO()
        with patch("sys.stdout", buf), patch("builtins.input", lambda _: next(simulated_inputs)):
            self.console.send_transfer()
        output = buf.getvalue()
        self.assertIn("SUCCESS! Transaction queued in Mempool", output)
        self.assertEqual(len(self.ledger.mempool), 1)

        # Mine the block
        buf = io.StringIO()
        with patch("sys.stdout", buf), patch("builtins.input", return_value="Miner"):
            self.console.mine_block()
        mine_output = buf.getvalue()
        self.assertIn("BLOCK MINED SUCCESSFULLY", mine_output)
        self.assertEqual(len(self.ledger.mempool), 0)
        self.assertEqual(self.ledger.height, 3)

    def test_verify_merkle_proof(self) -> None:
        # Verify transaction 0 in block 1
        simulated_inputs = iter(["1", "0"])
        buf = io.StringIO()
        with patch("sys.stdout", buf), patch("builtins.input", lambda _: next(simulated_inputs)):
            self.console.verify_merkle_proof()
        output = buf.getvalue()
        self.assertIn("MERKLE PROOF FOR TX #0 IN BLOCK #1", output)
        self.assertIn("PROOF RESULT: VALID", output)

    def test_simulate_tamper(self) -> None:
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            self.console.simulate_tamper()
        output = buf.getvalue()
        self.assertIn("CRYPTOGRAPHIC TAMPER FALLOUT REPORT", output)
        self.assertIn("Signature check failed", output)
        self.assertIn("Merkle root mismatch", output)
        self.assertIn("Full-Chain Validator throws TamperDetectedError", output)


if __name__ == "__main__":
    unittest.main()
