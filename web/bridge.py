"""
HTTP bridge between the browser frontend and the Blockchain-Lite ledger.

Standard library only (`http.server`, `json`, `queue`, `threading`). It lives
outside the `blockchain_lite` package so the package's import audit is unaffected.

- Serves `web/static/` (HTML/CSS/JS) and, when enabled, Manim renders.
- JSON API under `/api/*`. Read paths go through `LedgerServerDispatcher`, the
  same validation layer the TCP RPC server uses.
- `/events` is a Server-Sent Events stream: `tx_submitted`, `block_mined`,
  `difficulty_changed`, `autominer`, `copy_tampered`, `network_audit`,
  `ledger_repaired`, `person_joined`, `render_ready`.
- Every participant keeps a copy of the ledger (`web/network.py`); a periodic
  network check repairs tampered copies from the valid majority.

Demo custody: like the terminal console, the bridge holds the demo wallets and
signs transfers for them. That is fine for a classroom demo on loopback and is
NOT how a real wallet should work (see SECURITY.md). Binds to 127.0.0.1 by default.

Run:  python3 -m web.bridge            (http://127.0.0.1:8080)
      python3 -m web.bridge --render   (also render Manim videos after each block)
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import mimetypes
import queue
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from blockchain_lite.crypto.hashing import default_hasher  # noqa: E402
from blockchain_lite.interfaces import (  # noqa: E402
    TX_TYPE_COINBASE,
    BlockchainLiteError,
    HashInterface,
    ValidationError,
)
from blockchain_lite.ledger.chain import BlockchainLedger  # noqa: E402
from blockchain_lite.ledger.merkle import MerkleTree, hash_merkle_leaf  # noqa: E402
from blockchain_lite.models.block import Block  # noqa: E402
from blockchain_lite.models.transaction import Transaction  # noqa: E402
from blockchain_lite.network.server import LedgerServerDispatcher  # noqa: E402
from blockchain_lite.wallet.demo_wallets import create_demo_ledger_and_wallets  # noqa: E402
from blockchain_lite.wallet.wallet import Wallet  # noqa: E402
from web.network import LedgerNetwork  # noqa: E402

logger = logging.getLogger("blockchain_lite.web")

STATIC_DIR = Path(__file__).resolve().parent / "static"
DEFAULT_RENDER_DIR = STATIC_DIR / "renders"
MAX_BODY_BYTES = 64 * 1024
MAX_TRACE_ATTEMPTS = 64
SSE_HEARTBEAT_SECONDS = 15.0
MINER_LABEL = "Miner"
MAX_NAME_LENGTH = 20


# ============================================================================
# Event bus (Server-Sent Events fan-out)
# ============================================================================

class EventBus:
    """Fan-out of JSON events to every connected `/events` client."""

    def __init__(self, max_queue: int = 256) -> None:
        self._subscribers: List["queue.Queue[Tuple[str, Dict[str, Any]]]"] = []
        self._lock = threading.Lock()
        self._max_queue = max_queue

    def subscribe(self) -> "queue.Queue[Tuple[str, Dict[str, Any]]]":
        q: "queue.Queue[Tuple[str, Dict[str, Any]]]" = queue.Queue(maxsize=self._max_queue)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: "queue.Queue[Tuple[str, Dict[str, Any]]]") -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def publish(self, kind: str, data: Dict[str, Any]) -> None:
        with self._lock:
            subscribers = list(self._subscribers)
        for q in subscribers:
            try:
                q.put_nowait((kind, data))
            except queue.Full:
                logger.info("Dropping %s event for a slow SSE client", kind)

    @property
    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)


# ============================================================================
# Bridge state: ledger + demo wallets + JSON views
# ============================================================================

class BridgeState:
    """Everything the HTTP handler needs, with JSON-ready views of ledger objects."""

    def __init__(
        self,
        ledger: BlockchainLedger,
        wallets: Dict[str, Wallet],
        hasher: HashInterface,
        on_block_mined: Optional[Callable[[Dict[str, Any]], None]] = None,
        rsa_bits: int = 384,
        audit_interval: float = 20.0,
    ) -> None:
        self.ledger = ledger
        self.wallets = wallets
        self.hasher = hasher
        self.rsa_bits = rsa_bits
        self._people_lock = threading.Lock()
        self.dispatcher = LedgerServerDispatcher(ledger)
        self.events = EventBus()
        self.on_block_mined = on_block_mined
        self.autominer = AutoMiner(self)
        self._names = {w.address: name for name, w in wallets.items()}
        self.network = LedgerNetwork(ledger, hasher, list(wallets), self.events.publish, audit_interval)

    # ---------------------------------------------------------------- helpers

    def _rpc(self, method: str, **params: Any) -> Dict[str, Any]:
        response = self.dispatcher.handle_request({"method": method, "params": params})
        if not response.get("ok"):
            err = response.get("error", {})
            raise ValidationError(err.get("message", f"{method} failed"))
        return response["result"]

    def name_of(self, address: bytes) -> str:
        return self._names.get(address, address.hex()[:8])

    def _wallet(self, name: Any) -> Wallet:
        if not isinstance(name, str) or name not in self.wallets:
            raise ValidationError(f"Unknown wallet: {name!r}")
        return self.wallets[name]

    def _block(self, index: Any) -> Block:
        if isinstance(index, bool) or not isinstance(index, int):
            raise ValidationError("Block index must be an integer")
        blocks = self.ledger.blocks
        if index < 0 or index >= len(blocks):
            raise ValidationError(f"Block #{index} does not exist")
        return blocks[index]

    def tx_view(self, tx: Transaction) -> Dict[str, Any]:
        sender = None
        if tx.inputs:
            sender = self.name_of(tx.inputs[0].sender_address(self.hasher))
        return {
            "tx_id": tx.compute_tx_id(self.hasher).hex(),
            "type": "coinbase" if tx.tx_type == TX_TYPE_COINBASE else "transfer",
            "from": sender,
            "inputs": [{"tx_id": i.prev_tx_id.hex(), "index": i.output_index} for i in tx.inputs],
            "outputs": [
                {"to": self.name_of(o.recipient_address), "amount": o.amount} for o in tx.outputs
            ],
            "total": tx.total_output_amount,
            "timestamp": tx.timestamp,
        }

    def block_summary(self, block: Block) -> Dict[str, Any]:
        blocks = self.ledger.blocks
        prev_ts = blocks[block.index - 1].timestamp if block.index > 0 else None
        return {
            "index": block.index,
            "hash": block.block_hash.hex(),
            "previous_hash": block.previous_hash.hex(),
            "merkle_root": block.merkle_root.hex(),
            "timestamp": block.timestamp,
            "difficulty": block.difficulty,
            "nonce": block.nonce,
            "tx_count": len(block.transactions),
            "block_time": None if prev_ts is None else block.timestamp - prev_ts,
        }

    def consensus(self) -> Dict[str, Any]:
        """Difficulty schedule as the UI shows it: per-block target and the +1 / -1 thresholds."""
        p = self.ledger.params
        blocks = self.ledger.blocks
        iv = p.retarget_interval
        info: Dict[str, Any] = {
            "retargeting": iv > 0,
            "difficulty": blocks[-1].difficulty,
            "next_difficulty": self.ledger.calculate_next_difficulty(),
            "min_difficulty": p.min_difficulty,
            "max_difficulty": p.max_difficulty,
            "retarget_interval": iv,
            "auto_mining": self.autominer.running,
        }
        if iv <= 0:
            return info
        # expected_difficulty compares ts[-1] - ts[-interval] (interval-1 gaps) with
        # interval * target, so per block: faster than `fast` -> +1, slower than `slow` -> -1.
        per_gap = iv * p.target_block_time_seconds / (iv - 1)
        window = blocks[-iv:]
        gaps = [b.timestamp - a.timestamp for a, b in zip(window, window[1:])]
        info.update({
            "target_block_time": round(per_gap, 2),
            "fast_below": round(0.75 * per_gap, 2),
            "slow_above": round(1.33 * per_gap, 2),
            "window_avg_block_time": round(sum(gaps) / len(gaps), 2) if gaps else None,
            "blocks_until_retarget": (iv - len(blocks) % iv) % iv,
        })
        return info

    # ------------------------------------------------------------------ reads

    def state(self) -> Dict[str, Any]:
        info = self._rpc("get_chain_info")
        return {
            "chain": info,
            "consensus": self.consensus(),
            "blocks": [self.block_summary(b) for b in self.ledger.blocks],
            "mempool": [self.tx_view(tx) for tx in self.ledger.mempool],
            "wallets": self.wallet_list(),
            "network": self.network.view(),
        }

    def wallet_list(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": name,
                "address": w.address.hex(),
                "balance": self.ledger.get_balance(w.address),
            }
            for name, w in list(self.wallets.items())
        ]

    def block_detail(self, index: Any) -> Dict[str, Any]:
        block = self._block(index)
        tree = block.compute_merkle_tree(hasher=self.hasher)
        detail = self.block_summary(block)
        detail["header_hex"] = block.header_bytes().hex()
        detail["transactions"] = [self.tx_view(tx) for tx in block.transactions]
        detail["merkle_levels"] = [[h.hex() for h in level] for level in tree.levels]
        return detail

    def merkle_proof(self, index: Any, tx_index: Any) -> Dict[str, Any]:
        block = self._block(index)
        if isinstance(tx_index, bool) or not isinstance(tx_index, int):
            raise ValidationError("tx index must be an integer")
        if tx_index < 0 or tx_index >= len(block.transactions):
            raise ValidationError(f"Block #{index} has no transaction {tx_index}")
        tx_id = block.transactions[tx_index].compute_tx_id(self.hasher)
        rpc = self._rpc("get_merkle_proof", block_index=index, tx_id_hex=tx_id.hex())
        tree = block.compute_merkle_tree(hasher=self.hasher)
        proof = tree.get_proof_by_index(tx_index)
        # Node positions for highlighting: (level, index) on the path and their siblings.
        path, siblings, idx = [], [], tx_index
        for level_no, level in enumerate(tree.levels[:-1]):
            width = len(level) + (len(level) % 2)
            path.append([level_no, idx])
            sib = idx + 1 if idx % 2 == 0 else idx - 1
            siblings.append([level_no, min(sib, width - 1, len(level) - 1)])
            idx //= 2
        path.append([len(tree.levels) - 1, 0])
        return {
            "block_index": index,
            "tx_index": tx_index,
            "tx_id": tx_id.hex(),
            "merkle_root": rpc["merkle_root_hex"],
            "step_count": rpc["step_count"],
            "steps": [
                {"sibling": s.sibling_hash.hex(), "direction": s.direction} for s in proof.steps
            ],
            "verified": MerkleTree.verify_proof(proof, block.merkle_root, hasher=self.hasher),
            "path": path,
            "siblings": siblings,
        }

    def forge_trace(self, index: Any) -> Dict[str, Any]:
        """Step-by-step data for replaying how block `index` was built (Block Forge + Manim)."""
        block = self._block(index)
        detail = self.block_detail(index)
        txs = block.transactions

        # Step 2: one transaction through SHA-256, plus a real 1-bit avalanche.
        sample = txs[1] if len(txs) > 1 else txs[0]
        sample_bytes = sample.to_bytes()
        sample_id = sample.compute_tx_id(self.hasher)
        flipped = bytearray(sample_bytes)
        flipped[-1] ^= 0x01
        flipped_digest = self.hasher.hash_bytes(bytes(flipped))
        diff_bits = [
            (a ^ b) >> (7 - bit) & 1
            for a, b in zip(sample_id, flipped_digest)
            for bit in range(8)
        ]
        leaves = [hash_merkle_leaf(tx.compute_tx_id(self.hasher), hasher=self.hasher).hex() for tx in txs]

        # Step 4: re-run the nonce search the miner did, so the UI can replay it.
        first = max(0, block.nonce + 1 - MAX_TRACE_ATTEMPTS)
        attempts = []
        for nonce in range(first, block.nonce + 1):
            digest = block.compute_header_hash(nonce_override=nonce, hasher=self.hasher)
            attempts.append({"nonce": nonce, "hash": digest.hex(), "ok": nonce == block.nonce})

        spent = sum(len(tx.inputs) for tx in txs)
        created = sum(len(tx.outputs) for tx in txs)
        return {
            "block": detail,
            "hash_sample": {
                "tx_index": txs.index(sample),
                "tx_bytes_hex": sample_bytes.hex(),
                "tx_id": sample_id.hex(),
                "leaf": leaves[txs.index(sample)],
                "avalanche_bits": diff_bits,
                "avalanche_flipped": sum(diff_bits),
            },
            "leaves": leaves,
            "attempts": attempts,
            "hashes_tried": block.nonce + 1,
            "target_bits": block.difficulty,
            "utxo_delta": {"spent": spent, "created": created},
            "balances": {w["name"]: w["balance"] for w in self.wallet_list()},
        }

    # ----------------------------------------------------------------- writes

    def send(self, body: Dict[str, Any]) -> Dict[str, Any]:
        sender = self._wallet(body.get("from"))
        recipient = self._wallet(body.get("to"))
        if sender is recipient:
            raise ValidationError("Sender and recipient must differ")
        amount, fee = body.get("amount"), body.get("fee", 1)
        tx = sender.create_signed_transfer(
            recipient_address=recipient.address,
            amount=amount,
            spendable_utxos=self.ledger.get_spendable_utxos(sender.address),
            fee=fee,
        )
        # Submit the signed canonical bytes through the RPC layer, like a remote wallet would.
        result = self._rpc("submit_transaction", tx_bytes_hex=tx.to_bytes().hex())
        view = self.tx_view(tx)
        view["fee"] = fee
        self.events.publish("tx_submitted", {"tx": view, "mempool_size": result["mempool_size"]})
        return {"tx": view, "mempool_size": result["mempool_size"]}

    def mine(self, with_trace: bool = True) -> Dict[str, Any]:
        """Mine the mempool into a block, announce it, and announce any difficulty retarget."""
        miner = self._wallet(MINER_LABEL)
        block, stats = self.ledger.mine_pending_transactions(miner_address=miner.address)
        self.network.sync()  # gossip the new block to every ledger copy
        stats_view = {
            "hashes_tried": stats.hashes_tried,
            "elapsed_seconds": stats.elapsed_seconds,
            "hashes_per_second": stats.hashes_per_second,
        }
        consensus = self.consensus()
        self.events.publish("block_mined", {
            "block": self.block_summary(block), "stats": stats_view, "consensus": consensus,
        })
        if consensus["next_difficulty"] != block.difficulty:
            self.events.publish("difficulty_changed", {
                "from": block.difficulty,
                "to": consensus["next_difficulty"],
                "window_avg_block_time": consensus.get("window_avg_block_time"),
                "target_block_time": consensus.get("target_block_time"),
            })
        if not with_trace and self.on_block_mined is None:
            return {"block": self.block_summary(block), "stats": stats_view}
        trace = self.forge_trace(block.index)
        trace["stats"] = stats_view
        trace["consensus"] = consensus
        if self.on_block_mined is not None:
            self.on_block_mined(trace)
        return trace

    def tamper(self, body: Dict[str, Any]) -> Dict[str, Any]:
        block = self._block(body.get("block"))
        tx_index = body.get("tx", 0)
        report = self.ledger.trace_tamper_cascade(block.index, tx_index)
        return {
            "block_index": report.tampered_block_index,
            "tx_index": report.tampered_tx_index,
            "original_tx_id": report.original_tx_id_hex,
            "tampered_tx_id": report.tampered_tx_id_hex,
            "signature_valid_after_tamper": report.signature_valid_after_tamper,
            "original_merkle_root": report.original_merkle_root_hex,
            "recomputed_merkle_root": report.recomputed_merkle_root_hex,
            "merkle_root_matches_header": report.merkle_root_matches_header,
            "original_block_hash": report.original_block_hash_hex,
            "recomputed_block_hash": report.recomputed_block_hash_If_merkle_updated_hex,
            "downstream_broken": list(report.downstream_broken_block_indices),
            "chain_still_valid": self.ledger.validate_full_chain().is_valid,
        }

    def add_person(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """New participant: fresh RSA wallet, their own ledger copy, optional coins from the Miner."""
        name = body.get("name")
        if not isinstance(name, str):
            raise ValidationError("Name is required")
        name = " ".join(name.split())
        if not name or len(name) > MAX_NAME_LENGTH or not all(c.isalnum() or c in " -_" for c in name):
            raise ValidationError(f"Name must be 1-{MAX_NAME_LENGTH} letters, digits, spaces, - or _")
        fund = body.get("fund", 0)
        if isinstance(fund, bool) or not isinstance(fund, int) or fund < 0:
            raise ValidationError("Starting coins must be a whole number, 0 or more")
        with self._people_lock:
            if name.lower() in {n.lower() for n in self.wallets}:
                raise ValidationError(f"{name} already exists")
            wallet = Wallet.generate(label=name, bit_length=self.rsa_bits)
            self.wallets[name] = wallet
            self._names[wallet.address] = name
            self.network.add_peer(name)
        funded = None
        fund_error = None
        if fund:
            try:
                funded = self.send({"from": MINER_LABEL, "to": name, "amount": fund, "fee": 1})["tx"]
            except BlockchainLiteError as exc:
                fund_error = str(exc)
        person = {"name": name, "address": wallet.address.hex(), "balance": 0}
        self.events.publish("person_joined", {"person": person, "funding_tx": funded, "fund_error": fund_error})
        return {"person": person, "funding_tx": funded, "fund_error": fund_error}

    def tamper_copy(self, body: Dict[str, Any]) -> Dict[str, Any]:
        return self.network.tamper(body.get("name"), body.get("block"), body.get("tx", 0), body.get("amount"))


class AutoMiner:
    """Background miner that keeps producing blocks, like a real network's hash power.

    Each block takes as long as the nonce search needs at the current difficulty,
    so retargeting pulls the block time toward the target on its own.
    """

    def __init__(self, state: BridgeState) -> None:
        self._state = state
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and not self._stop.is_set()

    def start(self) -> None:
        with self._lock:
            if self.running:
                return
            self._stop = threading.Event()
            self._thread = threading.Thread(target=self._run, args=(self._stop,), name="auto-miner", daemon=True)
            self._thread.start()
        self._state.events.publish("autominer", {"running": True})

    def stop(self) -> None:
        with self._lock:
            self._stop.set()
        self._state.events.publish("autominer", {"running": False})

    def _run(self, stop: threading.Event) -> None:
        while not stop.is_set():
            try:
                self._state.mine(with_trace=False)
            except BlockchainLiteError as exc:  # tip moved under us: just try again
                logger.info("Auto-miner retry: %s", exc)
            stop.wait(0.05)


# ============================================================================
# HTTP handler
# ============================================================================

def _int_param(query: Dict[str, List[str]], key: str) -> int:
    values = query.get(key)
    if not values:
        raise ValidationError(f"Missing query parameter '{key}'")
    try:
        return int(values[0])
    except ValueError as exc:
        raise ValidationError(f"Query parameter '{key}' must be an integer") from exc


class BridgeHandler(BaseHTTPRequestHandler):
    server_version = "BlockchainLiteBridge/1.0"
    state: BridgeState  # set on the subclass by make_server()
    render_dir: Path

    def log_message(self, fmt: str, *args: Any) -> None:  # route through logging
        logger.debug("%s - %s", self.address_string(), fmt % args)

    # ---------------------------------------------------------------- output

    def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_error_json(self, status: int, exc: BaseException) -> None:
        self._send_json(status, {"ok": False, "error": {"type": type(exc).__name__, "message": str(exc)}})

    def _send_file(self, base: Path, rel: str) -> None:
        target = (base / rel).resolve()
        if base.resolve() not in target.parents and target != base.resolve():
            self.send_error(404)
            return
        if not target.is_file():
            self.send_error(404)
            return
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY_BYTES:
            raise ValidationError("Request body too large")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationError("Request body must be JSON") from exc
        if not isinstance(body, dict):
            raise ValidationError("Request body must be a JSON object")
        return body

    # ---------------------------------------------------------------- routes

    def do_GET(self) -> None:  # noqa: N802 (http.server naming)
        url = urlparse(self.path)
        query = parse_qs(url.query)
        try:
            if url.path in ("/", "/index.html"):
                self._send_file(STATIC_DIR, "index.html")
            elif url.path.startswith("/static/"):
                self._send_file(STATIC_DIR, url.path[len("/static/"):])
            elif url.path.startswith("/renders/"):
                self._send_file(self.render_dir, url.path[len("/renders/"):])
            elif url.path == "/events":
                self._stream_events()
            elif url.path == "/api/state":
                self._send_json(200, {"ok": True, "result": self.state.state()})
            elif url.path == "/api/block":
                self._send_json(200, {"ok": True, "result": self.state.block_detail(_int_param(query, "index"))})
            elif url.path == "/api/proof":
                result = self.state.merkle_proof(_int_param(query, "block"), _int_param(query, "tx"))
                self._send_json(200, {"ok": True, "result": result})
            elif url.path == "/api/trace":
                self._send_json(200, {"ok": True, "result": self.state.forge_trace(_int_param(query, "index"))})
            elif url.path == "/api/network":
                self._send_json(200, {"ok": True, "result": self.state.network.view()})
            elif url.path == "/api/renders":
                self._send_json(200, {"ok": True, "result": _list_renders(self.render_dir)})
            else:
                self.send_error(404)
        except (BlockchainLiteError, ValueError, TypeError) as exc:
            self._send_error_json(400, exc)

    def do_POST(self) -> None:  # noqa: N802
        url = urlparse(self.path)
        try:
            body = self._read_json()
            if url.path == "/api/tx":
                result = self.state.send(body)
            elif url.path == "/api/mine":
                result = self.state.mine()
            elif url.path == "/api/tamper":
                result = self.state.tamper(body)
            elif url.path == "/api/people":
                result = self.state.add_person(body)
            elif url.path == "/api/network/tamper":
                result = self.state.tamper_copy(body)
            elif url.path == "/api/network/audit":
                result = self.state.network.audit()
            elif url.path == "/api/autominer":
                if body.get("on"):
                    self.state.autominer.start()
                else:
                    self.state.autominer.stop()
                result = {"running": self.state.autominer.running}
            else:
                self.send_error(404)
                return
            self._send_json(200, {"ok": True, "result": result})
        except (BlockchainLiteError, ValueError, TypeError) as exc:
            self._send_error_json(400, exc)

    def _stream_events(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        q = self.state.events.subscribe()
        try:
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()
            while True:
                try:
                    kind, data = q.get(timeout=SSE_HEARTBEAT_SECONDS)
                except queue.Empty:
                    self.wfile.write(b": ping\n\n")
                else:
                    payload = json.dumps(data)
                    self.wfile.write(f"event: {kind}\ndata: {payload}\n\n".encode("utf-8"))
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            self.state.events.unsubscribe(q)


def _list_renders(render_dir: Path) -> List[str]:
    if not render_dir.is_dir():
        return []
    return sorted(p.name for p in render_dir.glob("*.mp4"))


# ============================================================================
# Wiring
# ============================================================================

def build_state(
    fast_hash: bool = True,
    rsa_bits: int = 384,
    on_block_mined: Optional[Callable[[Dict[str, Any]], None]] = None,
    block_time: float = 10.0,
    retarget_interval: int = 4,
    max_difficulty: int = 24,
    audit_interval: float = 20.0,
) -> BridgeState:
    """Create the demo ledger (10 pre-mined blocks, 20 wallets + Miner) behind a bridge.

    `block_time` is the per-block target; `retarget_interval=0` keeps difficulty fixed.
    """
    if fast_hash:
        from blockchain_lite.crypto.fast_hash import HashlibSHA256

        hasher: HashInterface = HashlibSHA256()
    else:
        hasher = default_hasher
    if retarget_interval == 1:
        raise ValueError("retarget_interval must be 0 (off) or at least 2")
    # The consensus window covers interval-1 gaps measured against interval * target,
    # so scale the protocol parameter to make `block_time` the real per-block target.
    target = block_time * (retarget_interval - 1) / retarget_interval if retarget_interval else block_time
    ledger, wallets = create_demo_ledger_and_wallets(
        hasher=hasher,
        rsa_bits=rsa_bits,
        retarget_interval=retarget_interval,
        target_block_time=target,
        max_difficulty=max_difficulty,
    )
    return BridgeState(ledger, wallets, hasher, on_block_mined=on_block_mined,
                       rsa_bits=rsa_bits, audit_interval=audit_interval)


class BridgeServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request: Any, client_address: Any) -> None:
        # Browsers drop keep-alive and SSE sockets all the time (reloads, tab closes).
        if isinstance(sys.exc_info()[1], (ConnectionResetError, BrokenPipeError)):
            return
        super().handle_error(request, client_address)


def make_server(
    state: BridgeState,
    host: str = "127.0.0.1",
    port: int = 8080,
    render_dir: Path = DEFAULT_RENDER_DIR,
) -> ThreadingHTTPServer:
    handler = type("BoundBridgeHandler", (BridgeHandler,), {"state": state, "render_dir": render_dir})
    return BridgeServer((host, port), handler)


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Blockchain-Lite web frontend bridge")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument(
        "--bit-level-hash", action="store_true",
        help="use the from-scratch bit-level SHA-256 (slow) instead of the bit-identical hashlib backend",
    )
    parser.add_argument("--rsa-bits", type=int, default=384)
    parser.add_argument("--block-time", type=float, default=10.0, help="target seconds per block (default 10)")
    parser.add_argument("--retarget-interval", type=int, default=4,
                        help="retarget difficulty every N blocks; 0 = fixed difficulty (default 4)")
    parser.add_argument("--max-difficulty", type=int, default=24)
    parser.add_argument("--auto-mine", action="store_true", help="start the background miner right away")
    parser.add_argument("--audit-interval", type=float, default=20.0,
                        help="seconds between network checks of everyone's ledger copy (default 20)")
    parser.add_argument("--render", action="store_true", help="render Manim videos after each mined block")
    parser.add_argument("--render-quality", default="l", choices=["l", "m", "h"])
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if not _is_loopback(args.host):
        logger.warning("Binding to %s: the bridge signs with demo keys; keep it off untrusted networks", args.host)

    on_mined = None
    state_holder: Dict[str, BridgeState] = {}
    if args.render:
        from viz.render import RenderQueue

        renders = RenderQueue(DEFAULT_RENDER_DIR, quality=args.render_quality)
        if not renders.available:
            logger.warning("Manim is not installed; --render is ignored (pip install manim)")
        else:
            def on_mined(trace: Dict[str, Any]) -> None:
                renders.submit(
                    trace,
                    on_done=lambda files: state_holder["s"].events.publish(
                        "render_ready", {"block_index": trace["block"]["index"], "files": files}
                    ),
                )

    logger.info("Building demo chain (%s hashing)...", "bit-level" if args.bit_level_hash else "fast")
    t0 = time.perf_counter()
    state = build_state(
        fast_hash=not args.bit_level_hash,
        rsa_bits=args.rsa_bits,
        on_block_mined=on_mined,
        block_time=args.block_time,
        retarget_interval=args.retarget_interval,
        max_difficulty=args.max_difficulty,
        audit_interval=args.audit_interval,
    )
    state_holder["s"] = state
    state.network.start()
    logger.info("Ready in %.1fs: %d blocks", time.perf_counter() - t0, state.ledger.height)

    if args.auto_mine:
        state.autominer.start()
    server = make_server(state, args.host, args.port)
    logger.info("Open http://%s:%d", args.host, args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
