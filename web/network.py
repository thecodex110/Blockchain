"""
Every person keeps their own copy of the ledger; a periodic network check repairs tampered copies.

This simulates the part of a real blockchain that the single-node core leaves out:
many independent copies of the same chain.

- Each participant (demo wallet or a person added later) is a `Peer` holding a list
  of blocks. Blocks are immutable, so honest copies share the same objects and a
  copy costs one list.
- New blocks are gossiped: `sync()` appends whatever the authoritative ledger has
  that a copy does not.
- `tamper()` edits one transaction amount inside one person's copy, the way an
  attacker editing their own file would. The stored header (Merkle root, block
  hash) is left as it was, so the edit is visible to anyone who re-checks it.
- `audit()` is the network check. Each copy is checked on its own (Merkle roots,
  header hashes, Proof-of-Work, `previous_hash` links); invalid copies cannot vote.
  The valid copies are grouped by content, the largest group is the majority
  ledger, and every copy that disagrees with it is replaced by it.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from blockchain_lite.interfaces import BlockchainLiteError, HashInterface, ValidationError
from blockchain_lite.ledger.chain import BlockchainLedger
from blockchain_lite.ledger.pow import verify_block_pow
from blockchain_lite.models.block import Block
from blockchain_lite.models.transaction import Transaction, TxOutput

Publish = Callable[[str, Dict[str, Any]], None]


@dataclass
class Peer:
    name: str
    blocks: List[Block]
    tampered_block: Optional[int] = None      # set by tamper(), cleared by a repair
    tampered_at: Optional[float] = None
    repaired_at: Optional[float] = None
    repairs: int = 0
    joined_at: float = field(default_factory=time.time)


class LedgerNetwork:
    """Ledger copies for every participant, gossip, tampering and majority repair."""

    def __init__(
        self,
        ledger: BlockchainLedger,
        hasher: HashInterface,
        names: List[str],
        publish: Publish,
        audit_interval: float = 20.0,
    ) -> None:
        self._ledger = ledger
        self._hasher = hasher
        self._publish = publish
        self._lock = threading.RLock()
        self._peers: Dict[str, Peer] = {}
        # id(block) -> (block, ok, digest). Holding the block keeps its id from being reused.
        self._block_cache: Dict[int, Tuple[Block, bool, bytes]] = {}
        self.audit_interval = audit_interval
        self.next_audit_at = time.time() + audit_interval
        self.last_audit: Optional[Dict[str, Any]] = None
        self._stop = threading.Event()
        chain = list(ledger.blocks)
        for name in names:
            self._peers[name] = Peer(name=name, blocks=list(chain))

    # ---------------------------------------------------------------- peers

    def add_peer(self, name: str) -> Peer:
        """A new participant downloads the current majority ledger."""
        with self._lock:
            if name in self._peers:
                raise ValidationError(f"{name} already has a ledger copy")
            source = self._majority_blocks() or list(self._ledger.blocks)
            peer = Peer(name=name, blocks=list(source))
            self._peers[name] = peer
            return peer

    def sync(self) -> None:
        """Gossip: give every copy the blocks it is missing from the authoritative chain."""
        chain = self._ledger.blocks
        with self._lock:
            for peer in self._peers.values():
                if len(peer.blocks) < len(chain):
                    peer.blocks.extend(chain[len(peer.blocks):])

    # --------------------------------------------------------------- tamper

    def tamper(self, name: str, block_index: int, tx_index: int, new_amount: int) -> Dict[str, Any]:
        """Change output 0 of one transaction in one person's copy, leaving the header untouched."""
        if isinstance(new_amount, bool) or not isinstance(new_amount, int) or new_amount < 1:
            raise ValidationError("New amount must be a positive whole number")
        with self._lock:
            peer = self._peer(name)
            if not isinstance(block_index, int) or not 0 < block_index < len(peer.blocks):
                raise ValidationError("Pick a block between Genesis and the tip")
            original = peer.blocks[block_index]
            if not isinstance(tx_index, int) or not 0 <= tx_index < len(original.transactions):
                raise ValidationError(f"Block #{block_index} has no transaction {tx_index}")
            tx = original.transactions[tx_index]
            if tx.outputs[0].amount == new_amount:
                raise ValidationError("That is the amount already recorded; pick a different one")

            outputs = list(tx.outputs)
            outputs[0] = TxOutput(amount=new_amount, recipient_address=outputs[0].recipient_address)
            forged_tx = Transaction(tx_type=tx.tx_type, timestamp=tx.timestamp, inputs=tx.inputs,
                                    outputs=tuple(outputs))
            txs = list(original.transactions)
            txs[tx_index] = forged_tx
            forged = Block(
                index=original.index,
                previous_hash=original.previous_hash,
                merkle_root=original.merkle_root,
                timestamp=original.timestamp,
                difficulty=original.difficulty,
                nonce=original.nonce,
                transactions=tuple(txs),
                block_hash=original.block_hash,
            )
            honest = list(peer.blocks)
            peer.blocks[block_index] = forged
            peer.tampered_block = block_index if peer.tampered_block is None else min(peer.tampered_block, block_index)
            peer.tampered_at = time.time()

            report = self._ledger.validator.trace_tamper_cascade(
                original_chain=honest, tampered_chain=peer.blocks,
                block_index=block_index, tx_index=tx_index,
            )
        result = {
            "name": name,
            "block_index": block_index,
            "tx_index": tx_index,
            "old_amount": tx.outputs[0].amount,
            "new_amount": new_amount,
            "original_tx_id": report.original_tx_id_hex,
            "tampered_tx_id": report.tampered_tx_id_hex,
            "signature_valid_after_tamper": report.signature_valid_after_tamper,
            "original_merkle_root": report.original_merkle_root_hex,
            "recomputed_merkle_root": report.recomputed_merkle_root_hex,
            "merkle_root_matches_header": report.merkle_root_matches_header,
            "original_block_hash": report.original_block_hash_hex,
            "recomputed_block_hash": report.recomputed_block_hash_If_merkle_updated_hex,
            "downstream_broken": list(report.downstream_broken_block_indices),
            "next_audit_in": max(0.0, self.next_audit_at - time.time()),
        }
        self._publish("copy_tampered", {
            "name": name, "block_index": block_index, "old_amount": result["old_amount"],
            "new_amount": new_amount, "next_audit_in": result["next_audit_in"],
        })
        return result

    # ---------------------------------------------------------------- audit

    def _check_block(self, block: Block, prev: Optional[Block]) -> Tuple[bool, bytes]:
        """Self-contained checks any peer can run on a block, cached per block object."""
        cached = self._block_cache.get(id(block))
        if cached is not None and cached[0] is block:
            ok, digest = cached[1], cached[2]
        else:
            digest = self._hasher.hash_bytes(block.to_bytes())
            try:
                block.verify_crystallized_integrity(hasher=self._hasher)
                if block.index > 0:
                    verify_block_pow(block, hasher=self._hasher)
                ok = True
            except BlockchainLiteError:
                ok = False
            self._block_cache[id(block)] = (block, ok, digest)
        if prev is not None and block.previous_hash != prev.block_hash:
            ok = False
        return ok, digest

    def _inspect(self, blocks: List[Block]) -> Tuple[Optional[int], bytes]:
        """(first bad block index or None, digest of the whole copy)."""
        bad: Optional[int] = None
        parts = []
        prev = None
        for block in blocks:
            ok, digest = self._check_block(block, prev)
            if not ok and bad is None:
                bad = block.index
            parts.append(digest)
            prev = block
        return bad, self._hasher.hash_bytes(b"".join(parts))

    def _groups(self) -> Tuple[Dict[str, Tuple[Optional[int], bytes]], List[Tuple[bytes, List[str]]]]:
        inspected = {name: self._inspect(peer.blocks) for name, peer in self._peers.items()}
        groups: Dict[bytes, List[str]] = {}
        for name, (bad, digest) in inspected.items():
            if bad is None:
                groups.setdefault(digest, []).append(name)
        ordered = sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[1][0]))
        return inspected, ordered

    def _majority_blocks(self) -> Optional[List[Block]]:
        _, ordered = self._groups()
        if not ordered:
            return None
        return self._peers[ordered[0][1][0]].blocks

    def audit(self) -> Dict[str, Any]:
        """The network check: find copies that disagree with the valid majority and repair them."""
        with self._lock:
            self.sync()
            inspected, ordered = self._groups()
            total = len(self._peers)
            repaired: List[Dict[str, Any]] = []
            if ordered:
                majority_digest, majority_names = ordered[0]
                majority = self._peers[majority_names[0]].blocks
                for name, peer in self._peers.items():
                    bad, digest = inspected[name]
                    if digest == majority_digest:
                        continue
                    first_diff = next(
                        (i for i, (a, b) in enumerate(zip(peer.blocks, majority)) if a is not b),
                        min(len(peer.blocks), len(majority)),
                    )
                    peer.blocks = list(majority)
                    peer.tampered_block = None
                    peer.repaired_at = time.time()
                    peer.repairs += 1
                    repaired.append({
                        "name": name,
                        "block_index": bad if bad is not None else first_diff,
                        "reason": "failed its own checks" if bad is not None else "disagreed with the majority",
                    })
                majority_size = len(majority_names)
            else:
                majority_size = 0
            invalid_left = [n for n, (bad, _) in inspected.items() if bad is not None and not ordered]
            self.next_audit_at = time.time() + self.audit_interval
            summary = {
                "at": time.time(),
                "copies": total,
                "majority_size": majority_size,
                "valid_copies": sum(1 for bad, _ in inspected.values() if bad is None),
                "repaired": repaired,
                "unrepairable": invalid_left,
                "next_audit_in": self.audit_interval,
            }
            self.last_audit = summary
        self._publish("network_audit", summary)
        for item in repaired:
            self._publish("ledger_repaired", {**item, "majority_size": majority_size, "copies": total})
        return summary

    # ----------------------------------------------------------- scheduling

    def start(self) -> None:
        threading.Thread(target=self._loop, name="network-audit", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.wait(0.5):
            if time.time() >= self.next_audit_at:
                try:
                    self.audit()
                except Exception:  # never let one failed check kill the schedule
                    self.next_audit_at = time.time() + self.audit_interval

    # ---------------------------------------------------------------- views

    def _peer(self, name: Any) -> Peer:
        if not isinstance(name, str) or name not in self._peers:
            raise ValidationError(f"Unknown person: {name!r}")
        return self._peers[name]

    def view(self) -> Dict[str, Any]:
        with self._lock:
            peers = [
                {
                    "name": p.name,
                    "height": len(p.blocks),
                    "tip": p.blocks[-1].block_hash.hex() if p.blocks else None,
                    "status": "tampered" if p.tampered_block is not None else "ok",
                    "tampered_block": p.tampered_block,
                    "tampered_at": p.tampered_at,
                    "repaired_at": p.repaired_at,
                    "repairs": p.repairs,
                }
                for p in self._peers.values()
            ]
            return {
                "peers": peers,
                "audit_interval": self.audit_interval,
                "next_audit_in": max(0.0, self.next_audit_at - time.time()),
                "last_audit": self.last_audit,
            }

    def blocks_of(self, name: str) -> List[Block]:
        with self._lock:
            return list(self._peer(name).blocks)
