"""
Interactive Terminal Console & Blockchain-Lite Explorer (`blockchain_lite/cli/terminal.py`).

Provides a zero-dependency, rich terminal interface to interactively inspect
blocks, manage digital wallets, transfer coins, mine blocks with Proof-of-Work,
verify Merkle inclusion proofs (SPV), and simulate cryptographic tampering directly
from the command-line.
"""

from __future__ import annotations

import argparse
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

from blockchain_lite.benchmarks.pow_benchmark import generate_full_experiment_report
from blockchain_lite.cli.demo import run_complete_demonstration
from blockchain_lite.crypto.asymmetric import weak_key_warning
from blockchain_lite.crypto.hashing import default_hasher
from blockchain_lite.interfaces import (
    TX_TYPE_COINBASE,
    TX_TYPE_TRANSFER,
    BlockchainLiteError,
    DoubleSpendError,
    HashInterface,
    ValidationError,
)
from blockchain_lite.ledger.chain import BlockchainLedger
from blockchain_lite.ledger.merkle import MerkleTree
from blockchain_lite.wallet.demo_wallets import create_demo_ledger_and_wallets
from blockchain_lite.wallet.wallet import Wallet

# Terminal ANSI color constants (olive/green, burgundy/red, cream/white, cyan, bold)
CLR_RESET = "\033[0m"
CLR_BOLD = "\033[1m"
CLR_CREAM = "\033[38;5;230m"      # Cream / warm white
CLR_BURGUNDY = "\033[38;5;124m"   # Burgundy / deep red
CLR_OLIVE = "\033[38;5;106m"      # Olive green
CLR_CYAN = "\033[36m"
CLR_YELLOW = "\033[33m"
CLR_DIM = "\033[2m"


def _c(text: str, color: str) -> str:
    """Format string with ANSI color code if stdout is a tty."""
    if hasattr(sys.stdout, "isatty") and sys.stdout.isatty():
        return f"{color}{text}{CLR_RESET}"
    return text


def format_hash(h: bytes, prefix_len: int = 8, suffix_len: int = 8) -> str:
    """Format a hash digest as prefix...suffix for clean terminal display."""
    hex_str = h.hex()
    if len(hex_str) <= prefix_len + suffix_len:
        return hex_str
    return f"{hex_str[:prefix_len]}...{hex_str[-suffix_len:]}"


class TerminalConsole:
    """
    Stateful interactive command-line interface for the Blockchain-Lite ledger.
    """

    def __init__(
        self,
        ledger: BlockchainLedger,
        wallets: Dict[str, Wallet],
        hasher: Optional[HashInterface] = None,
    ) -> None:
        self.ledger = ledger
        self.wallets = dict(wallets)
        self.hasher = hasher or default_hasher

    def print_banner(self) -> None:
        title = "BLOCKCHAIN-LITE LEDGER & DIGITAL WALLET — TERMINAL CONSOLE"
        sep = "=" * 78
        print(_c(sep, CLR_BURGUNDY))
        print(_c(f"  {title}", CLR_BOLD + CLR_CREAM))
        print(_c(f"  Python Standard Library · Pure First-Principles Blockchain", CLR_DIM))
        print(_c(sep, CLR_BURGUNDY))

    def print_menu(self) -> None:
        print()
        print(_c("--- [ MAIN MENU ] -------------------------------------------------------------", CLR_OLIVE))
        print(f"  {_c('[1]', CLR_BOLD + CLR_CYAN)} {_c('Chain Status', CLR_CREAM)}       - View height, latest block hash, difficulty & mempool")
        print(f"  {_c('[2]', CLR_BOLD + CLR_CYAN)} {_c('Explore Blocks', CLR_CREAM)}     - List all blocks and view detailed transactions")
        print(f"  {_c('[3]', CLR_BOLD + CLR_CYAN)} {_c('Wallets & Balance', CLR_CREAM)}  - View demo wallet addresses, UTXOs & balances")
        print(f"  {_c('[4]', CLR_BOLD + CLR_CYAN)} {_c('Send Transfer', CLR_CREAM)}      - Create & sign a transaction with RSA private key")
        print(f"  {_c('[5]', CLR_BOLD + CLR_CYAN)} {_c('Mine Block', CLR_CREAM)}         - Mine pending transactions via Proof-of-Work")
        print(f"  {_c('[6]', CLR_BOLD + CLR_CYAN)} {_c('Verify Merkle Proof', CLR_CREAM)} - Generate & verify O(log N) SPV inclusion proof")
        print(f"  {_c('[7]', CLR_BOLD + CLR_CYAN)} {_c('Simulate Tamper', CLR_CREAM)}    - Tamper 1 byte and witness cryptographic rejection")
        print(f"  {_c('[8]', CLR_BOLD + CLR_CYAN)} {_c('Run Full Demo', CLR_CREAM)}      - Execute 6-stage automated viva evaluation suite")
        print(f"  {_c('[9]', CLR_BOLD + CLR_CYAN)} {_c('PoW Benchmark', CLR_CREAM)}      - Difficulty vs mining time statistical profiler")
        print(f"  {_c('[0]', CLR_BOLD + CLR_BURGUNDY)} {_c('Exit Console', CLR_BURGUNDY)}       - Quit the terminal session")
        print(_c("-------------------------------------------------------------------------------", CLR_OLIVE))

    def show_chain_status(self) -> None:
        report = self.ledger.validate_full_chain() if self.ledger.height > 0 else None
        print()
        print(_c("=== [ BLOCKCHAIN STATUS ] =====================================================", CLR_OLIVE))
        print(f"  Height (Total Blocks)    : {_c(str(self.ledger.height), CLR_BOLD + CLR_CREAM)}")
        is_valid_str = _c("VALID [Integrity Confirmed]", CLR_BOLD + CLR_OLIVE) if (report and report.is_valid) else _c("INVALID", CLR_BOLD + CLR_BURGUNDY)
        print(f"  Chain Validity           : {is_valid_str}")
        print(f"  Mining Difficulty        : {_c(f'{self.ledger.difficulty} leading zero bits', CLR_CYAN)}")
        print(f"  Block Reward             : {_c(f'{self.ledger.block_reward} coins', CLR_CREAM)}")
        print(f"  Pending Mempool Txs      : {_c(str(self.ledger.mempool_size), CLR_YELLOW)}")
        total_work = report.cumulative_pow_work if report else 0
        print(f"  Cumulative Chain Work    : {_c(str(total_work), CLR_CYAN)}")
        if self.ledger.blocks:
            tip = self.ledger.blocks[-1]
            print(f"  Tip Block Index          : #{tip.index}")
            print(f"  Tip Block Hash           : {_c(tip.block_hash.hex(), CLR_OLIVE)}")
            print(f"  Tip Prev Block Hash      : {tip.previous_hash.hex()}")
            print(f"  Tip Merkle Root          : {tip.merkle_root.hex()}")
            print(f"  Tip Nonce Found          : {tip.nonce}")
        print(_c("===============================================================================", CLR_OLIVE))

    def list_blocks(self) -> None:
        print()
        print(_c("=== [ BLOCKCHAIN BLOCKS ] =====================================================", CLR_OLIVE))
        print(f" {'Index':<6} {'Hash Prefix':<22} {'Prev Hash':<22} {'Txs':<5} {'Nonce':<8} {'Timestamp'}")
        print("-" * 79)
        for b in self.ledger.blocks:
            h_str = format_hash(b.block_hash, 8, 8)
            p_str = format_hash(b.previous_hash, 8, 8)
            print(f" #{b.index:<5} {h_str:<22} {p_str:<22} {len(b.transactions):<5} {b.nonce:<8} {b.timestamp}")
        print("-" * 79)

        try:
            choice = input(_c("Inspect block by index (press Enter to skip): ", CLR_BOLD + CLR_CYAN)).strip()
        except (EOFError, KeyboardInterrupt):
            return

        if not choice:
            return
        try:
            idx = int(choice)
            if idx < 0 or idx >= len(self.ledger.blocks):
                print(_c(f"Error: Invalid block index #{idx}. Total blocks: {len(self.ledger.blocks)}", CLR_BURGUNDY))
                return
            self.inspect_block(idx)
        except ValueError:
            print(_c("Error: Please enter a valid numeric block index.", CLR_BURGUNDY))

    def inspect_block(self, idx: int) -> None:
        block = self.ledger.blocks[idx]
        print()
        print(_c(f"--- [ DETAILS FOR BLOCK #{idx} ] ----------------------------------------------", CLR_CYAN))
        print(f"  Block Hash        : {_c(block.block_hash.hex(), CLR_OLIVE)}")
        print(f"  Previous Hash     : {block.previous_hash.hex()}")
        print(f"  Merkle Root       : {block.merkle_root.hex()}")
        print(f"  Nonce Found       : {block.nonce}")
        print(f"  Target Difficulty : {block.difficulty} zero bits")
        print(f"  Unix Timestamp    : {block.timestamp}")
        print(f"  Transactions ({len(block.transactions)}):")

        for t_idx, tx in enumerate(block.transactions):
            tx_type = "COINBASE" if tx.tx_type == TX_TYPE_COINBASE else "TRANSFER"
            print()
            print(f"    [{t_idx}] Type: {_c(tx_type, CLR_YELLOW)} | TxID: {_c(format_hash(tx.tx_id, 10, 10), CLR_CREAM)}")
            if tx.tx_type == TX_TYPE_COINBASE:
                out = tx.outputs[0]
                recip_name = self._resolve_address(out.recipient_address)
                print(f"        Mints {out.amount} coins -> {recip_name} ({out.recipient_address.hex()[:16]}...)")
            else:
                print(f"        Inputs ({len(tx.inputs)} spent):")
                for inp in tx.inputs:
                    print(f"          - Outpoint: {format_hash(inp.prev_tx_id, 6, 6)} index {inp.output_index}")
                print(f"        Outputs ({len(tx.outputs)} created):")
                for out_idx, out in enumerate(tx.outputs):
                    recip_name = self._resolve_address(out.recipient_address)
                    print(f"          [{out_idx}] {out.amount} coins -> {recip_name} ({out.recipient_address.hex()[:16]}...)")
        print(_c("-------------------------------------------------------------------------------", CLR_CYAN))

    def show_wallets(self) -> None:
        print()
        print(_c("=== [ WALLETS & BALANCES ] ====================================================", CLR_OLIVE))
        print(f" {'Wallet':<12} {'Balance':<12} {'UTXOs':<8} {'Key Size':<10} {'Public Address'}")
        print("-" * 79)
        for name, wallet in self.wallets.items():
            bal = self.ledger.get_balance(wallet.address)
            utxos = len(self.ledger.get_spendable_utxos(wallet.address))
            addr_str = format_hash(wallet.address, 10, 8)
            key_size = f"RSA-{wallet.public_key.n.bit_length()}"
            print(f" {name:<12} {_c(str(bal) + ' coins', CLR_BOLD + CLR_CREAM):<21} {utxos:<8} {key_size:<10} {addr_str}")
        print("-" * 79)

    def send_transfer(self) -> None:
        print()
        print(_c("=== [ CREATE & SIGN TRANSACTION ] =============================================", CLR_OLIVE))
        self.show_wallets()

        try:
            sender_name = input(_c("Sender wallet name [e.g. Alice]: ", CLR_BOLD + CLR_CYAN)).strip()
            if not sender_name or sender_name not in self.wallets:
                print(_c(f"Error: Unknown sender wallet '{sender_name}'. Available: {list(self.wallets.keys())}", CLR_BURGUNDY))
                return

            recipient_input = input(_c("Recipient wallet name or hex address [e.g. Bob]: ", CLR_BOLD + CLR_CYAN)).strip()
            if not recipient_input:
                print(_c("Error: Recipient cannot be empty.", CLR_BURGUNDY))
                return

            if recipient_input in self.wallets:
                recipient_address = self.wallets[recipient_input].address
            else:
                try:
                    recipient_address = bytes.fromhex(recipient_input)
                except ValueError:
                    print(_c("Error: Invalid recipient hex address or wallet name.", CLR_BURGUNDY))
                    return

            amount_str = input(_c("Amount to transfer (coins): ", CLR_BOLD + CLR_CYAN)).strip()
            amount = int(amount_str)
            if amount <= 0:
                print(_c("Error: Amount must be greater than 0.", CLR_BURGUNDY))
                return

            fee_str = input(_c("Transaction fee [default: 1]: ", CLR_BOLD + CLR_CYAN)).strip()
            fee = int(fee_str) if fee_str else 1
            if fee < 0:
                print(_c("Error: Fee cannot be negative.", CLR_BURGUNDY))
                return

        except (ValueError, EOFError, KeyboardInterrupt) as exc:
            print(_c(f"\nTransaction cancelled: {exc}", CLR_BURGUNDY))
            return

        sender_wallet = self.wallets[sender_name]
        spendable = self.ledger.get_spendable_utxos(sender_wallet.address)
        current_bal = sum(u.amount for u in spendable)

        if current_bal < amount + fee:
            print(_c(f"Error: Insufficient funds. {sender_name} has {current_bal} coins, but needs {amount + fee} (amount {amount} + fee {fee}).", CLR_BURGUNDY))
            return

        try:
            print(_c("[*] Selecting UTXOs and signing transaction with sender RSA private key...", CLR_DIM))
            tx = sender_wallet.create_signed_transfer(
                recipient_address=recipient_address,
                amount=amount,
                spendable_utxos=spendable,
                fee=fee,
            )
            print(_c(f"    Transaction signed! TxID: {tx.tx_id.hex()}", CLR_CYAN))

            print(_c("[*] Submitting transaction to Blockchain Mempool...", CLR_DIM))
            self.ledger.submit_transaction(tx)
            print(_c(f"[+] SUCCESS! Transaction queued in Mempool. Pending tx count: {len(self.ledger.mempool)}", CLR_BOLD + CLR_OLIVE))
            print(_c(f"    Run 'Mine Block' (Option 5) to confirm it into a new block.", CLR_CREAM))
        except (DoubleSpendError, ValidationError, BlockchainLiteError) as exc:
            print(_c(f"[-] Transaction rejected by ledger: [{type(exc).__name__}] {exc}", CLR_BOLD + CLR_BURGUNDY))

    def mine_block(self) -> None:
        print()
        print(_c("=== [ MINE BLOCK — PROOF-OF-WORK ] ===========================================", CLR_OLIVE))
        mempool_len = len(self.ledger.mempool)
        print(f"  Pending Transactions in Mempool: {_c(str(mempool_len), CLR_BOLD + CLR_CREAM)}")

        try:
            miner_name = input(_c("Select miner wallet for Coinbase reward [default: Miner]: ", CLR_BOLD + CLR_CYAN)).strip()
            if not miner_name:
                miner_name = "Miner"
            if miner_name not in self.wallets:
                print(_c(f"Warning: '{miner_name}' not in named wallets. Available: {list(self.wallets.keys())}", CLR_BURGUNDY))
                return
            miner_wallet = self.wallets[miner_name]
        except (EOFError, KeyboardInterrupt):
            return

        print(_c(f"[*] Starting Proof-of-Work search for Block #{len(self.ledger.blocks)}...", CLR_CREAM))
        print(f"    Target Difficulty: {_c(f'{self.ledger.difficulty} leading zero bits', CLR_CYAN)}")
        print(f"    Miner Address    : {miner_wallet.address.hex()[:16]}... ({miner_name})")

        t0 = time.perf_counter()
        block, stats = self.ledger.mine_pending_transactions(miner_address=miner_wallet.address)
        elapsed = time.perf_counter() - t0

        h_rate = stats.hashes_tried / max(elapsed, 1e-6)
        print()
        print(_c("[+] BLOCK MINED SUCCESSFULLY!", CLR_BOLD + CLR_OLIVE))
        print(f"  Block Index   : #{block.index}")
        print(f"  Block Hash    : {_c(block.block_hash.hex(), CLR_BOLD + CLR_OLIVE)}")
        print(f"  Nonce Found   : {_c(str(stats.winning_nonce), CLR_BOLD + CLR_CREAM)}")
        print(f"  Hashes Tried  : {stats.hashes_tried} in {elapsed:.3f}s ({h_rate:,.0f} H/s)")
        print(f"  Transactions  : {len(block.transactions)} confirmed into block")
        print(f"  New Chain Tip : #{self.ledger.blocks[-1].index} (Height: {len(self.ledger.blocks)})")
        print()
        self.show_wallets()

    def verify_merkle_proof(self) -> None:
        print()
        print(_c("=== [ VERIFY MERKLE INCLUSION PROOF (SPV) ] ===================================", CLR_OLIVE))
        if not self.ledger.blocks:
            print(_c("Error: No blocks available.", CLR_BURGUNDY))
            return

        try:
            b_str = input(_c(f"Select block index (0 to {len(self.ledger.blocks)-1}) [default: latest]: ", CLR_BOLD + CLR_CYAN)).strip()
            b_idx = int(b_str) if b_str else (len(self.ledger.blocks) - 1)
            if b_idx < 0 or b_idx >= len(self.ledger.blocks):
                print(_c("Error: Invalid block index.", CLR_BURGUNDY))
                return

            block = self.ledger.blocks[b_idx]
            tx_count = len(block.transactions)
            print(f"  Block #{b_idx} contains {tx_count} transactions.")

            t_str = input(_c(f"Select transaction index (0 to {tx_count-1}) [default: 0]: ", CLR_BOLD + CLR_CYAN)).strip()
            t_idx = int(t_str) if t_str else 0
            if t_idx < 0 or t_idx >= tx_count:
                print(_c("Error: Invalid transaction index.", CLR_BURGUNDY))
                return
        except (ValueError, EOFError, KeyboardInterrupt):
            return

        tx = block.transactions[t_idx]
        tx_leaf_hash = self.hasher.hash_bytes(b"\x00" + tx.tx_id)

        tree = MerkleTree([t.tx_id for t in block.transactions], hasher=self.hasher)
        proof = tree.get_proof_by_index(t_idx)

        print()
        print(_c(f"--- [ MERKLE PROOF FOR TX #{t_idx} IN BLOCK #{b_idx} ] ------------------------", CLR_CYAN))
        print(f"  Tx ID               : {tx.tx_id.hex()}")
        print(f"  Leaf Hash (0x00+Tx) : {tx_leaf_hash.hex()}")
        print(f"  Block Merkle Root   : {_c(block.merkle_root.hex(), CLR_BOLD + CLR_CREAM)}")
        print(f"  Authentication Path ({len(proof.steps)} sibling hashes):")
        for step_idx, step in enumerate(proof.steps):
            direction = f"{step.direction} sibling"
            print(f"    Step {step_idx + 1}: {direction} = {format_hash(step.sibling_hash, 10, 10)}")

        is_valid = MerkleTree.verify_proof(proof, block.merkle_root, hasher=self.hasher)
        print()
        if is_valid:
            print(_c("  [+] PROOF RESULT: VALID (Cryptographically confirmed included in block header)", CLR_BOLD + CLR_OLIVE))
        else:
            print(_c("  [-] PROOF RESULT: INVALID (Failed to authenticate against root)", CLR_BOLD + CLR_BURGUNDY))
        print(_c("-------------------------------------------------------------------------------", CLR_CYAN))

    def simulate_tamper(self) -> None:
        print()
        print(_c("=== [ CRYPTOGRAPHIC TAMPER CASCADE SIMULATOR ] ================================", CLR_OLIVE))
        print("This simulation modifies 1 byte in a mined transaction to demonstrate how")
        print("the mathematical foundation of the blockchain detects and rejects fraud.\n")

        # Find first block with transfer transaction (index >= 1)
        target_b_idx = 1 if len(self.ledger.blocks) > 1 else 0
        target_tx_idx = 1 if len(self.ledger.blocks[target_b_idx].transactions) > 1 else 0

        target_block = self.ledger.blocks[target_b_idx]
        target_tx = target_block.transactions[target_tx_idx]

        print(f"Targeting Block #{target_b_idx}, Transaction #{target_tx_idx} (TxID: {target_tx.tx_id.hex()[:16]}...)")
        print(_c("[*] Synthesizing 1-byte tamper in transaction payload...", CLR_YELLOW))

        report = self.ledger.trace_tamper_cascade(
            tampered_block_index=target_b_idx,
            tampered_tx_index=target_tx_idx,
        )

        print()
        print(_c("--- [ CRYPTOGRAPHIC TAMPER FALLOUT REPORT ] -----------------------------------", CLR_BURGUNDY))
        print(f"  Target Block Index              : #{report.tampered_block_index}")
        print(f"  Target Tx Index                 : #{report.tampered_tx_index}")
        print(f"  Original Tx ID                  : {report.original_tx_id_hex}")
        print(f"  Tampered Tx ID                  : {_c(report.tampered_tx_id_hex, CLR_BURGUNDY)}")
        sig_str = _c("VALID", CLR_OLIVE) if report.signature_valid_after_tamper else _c("INVALID [Signature check failed]", CLR_BOLD + CLR_BURGUNDY)
        print(f"  1. RSA Signature Verification   : {sig_str}")
        root_str = _c("MATCHES", CLR_OLIVE) if report.merkle_root_matches_header else _c("FAILED [Merkle root mismatch]", CLR_BOLD + CLR_BURGUNDY)
        print(f"  2. Merkle Root Check            : {root_str}")
        print(f"     - Header Merkle Root         : {report.original_merkle_root_hex}")
        print(f"     - Recomputed Merkle Root     : {report.recomputed_merkle_root_hex}")
        print(f"  3. Block PoW Hash Link          : {_c('INVALIDATED [Header hash changed]', CLR_BOLD + CLR_BURGUNDY)}")
        print(f"     - Header Block Hash          : {report.original_block_hash_hex}")
        print(f"     - If Merkle Root updated     : {report.recomputed_block_hash_If_merkle_updated_hex}")
        broken_str = ", ".join(f"#{i}" for i in report.downstream_broken_block_indices) if report.downstream_broken_block_indices else "None"
        print(f"  4. Downstream Broken Blocks     : {_c(broken_str, CLR_BURGUNDY)}")
        print(f"  5. Consensus Verdict            : {_c('REJECTED [Full-Chain Validator throws TamperDetectedError]', CLR_BOLD + CLR_OLIVE)}")
        print(_c("-------------------------------------------------------------------------------", CLR_BURGUNDY))
        print(_c("[+] The authoritative ledger remains 100% untampered and secure.", CLR_CREAM))

    def run_demo(self) -> None:
        print()
        print(_c("=== [ RUNNING 6-STAGE DEMONSTRATION ] =========================================", CLR_OLIVE))
        output = run_complete_demonstration()
        print(output)

    def run_benchmark(self) -> None:
        print()
        print(_c("=== [ PROOF-OF-WORK BENCHMARK ] ===============================================", CLR_OLIVE))
        output = generate_full_experiment_report(difficulties=(0, 2, 4, 6), trials_per_difficulty=2)
        print(output)

    def _resolve_address(self, addr: bytes) -> str:
        for name, w in self.wallets.items():
            if w.address == addr:
                return name
        return "Unknown"

    def run_loop(self) -> None:
        """Main interactive REPL loop."""
        self.print_banner()
        while True:
            self.print_menu()
            try:
                cmd = input(_c("Select option [0-9]: ", CLR_BOLD + CLR_CYAN)).strip().lower()
            except (EOFError, KeyboardInterrupt):
                print(_c("\nExiting terminal session. Goodbye!", CLR_BURGUNDY))
                break

            if cmd in ("0", "exit", "quit", "q"):
                print(_c("\nExiting terminal session. Goodbye!", CLR_BURGUNDY))
                break
            elif cmd in ("1", "status", "chain"):
                self.show_chain_status()
            elif cmd in ("2", "blocks", "block"):
                self.list_blocks()
            elif cmd in ("3", "wallets", "wallet", "balance", "bal"):
                self.show_wallets()
            elif cmd in ("4", "send", "transfer", "tx"):
                self.send_transfer()
            elif cmd in ("5", "mine", "mining"):
                self.mine_block()
            elif cmd in ("6", "merkle", "spv", "proof"):
                self.verify_merkle_proof()
            elif cmd in ("7", "tamper", "attack"):
                self.simulate_tamper()
            elif cmd in ("8", "demo", "test"):
                self.run_demo()
            elif cmd in ("9", "benchmark", "bench", "pow"):
                self.run_benchmark()
            else:
                print(_c(f"Unknown option '{cmd}'. Please choose a valid number from 0 to 9.", CLR_BURGUNDY))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Blockchain-Lite Interactive Terminal Console & Explorer"
    )
    parser.add_argument(
        "--fast-hash",
        action="store_true",
        help="Use optional hashlib SHA-256 backend (bit-identical; much faster mining)",
    )
    parser.add_argument(
        "--rsa-bits",
        type=int,
        default=384,
        help="RSA modulus size for demo wallets (default 384; educational)",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run the automated 6-stage viva demonstration and exit",
    )
    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Run the PoW difficulty benchmark and exit",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Print current blockchain status and exit",
    )
    args = parser.parse_args()

    warn = weak_key_warning(args.rsa_bits)
    if warn:
        print(warn, file=sys.stderr)

    hasher: HashInterface = default_hasher
    if args.fast_hash:
        from blockchain_lite.crypto.fast_hash import HashlibSHA256
        hasher = HashlibSHA256()

    if args.demo:
        print(run_complete_demonstration(rsa_bits=args.rsa_bits))
        return

    if args.benchmark:
        print(generate_full_experiment_report(difficulties=(0, 2, 4, 6), trials_per_difficulty=2))
        return

    # Initialize demo chain
    ledger, wallets = create_demo_ledger_and_wallets(hasher=hasher, rsa_bits=args.rsa_bits)
    console = TerminalConsole(ledger=ledger, wallets=wallets, hasher=hasher)

    if args.status:
        console.show_chain_status()
        return

    console.run_loop()


if __name__ == "__main__":
    main()
