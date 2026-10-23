"""
Web bridge (web/bridge.py): JSON API, SSE events and static file serving,
exercised over a real loopback HTTP server.
"""

from __future__ import annotations

import json
import socket
import threading
import unittest
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from blockchain_lite.interfaces import ValidationError
from web.bridge import build_state, make_server
from web.gate import LOCKOUT_SECONDS, MAX_ATTEMPTS, PasscodeGate


class TestWebBridge(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.state = build_state(fast_hash=True)
        cls.server = make_server(cls.state, "127.0.0.1", 0)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def _req(self, path: str, body: Optional[Dict[str, Any]] = None, raw: Optional[bytes] = None):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(self.base + path, data=data, method="POST" if data is not None else "GET",
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def test_state_lists_chain_wallets_and_blocks(self) -> None:
        status, payload = self._req("/api/state")
        self.assertEqual(status, 200)
        result = payload["result"]
        self.assertTrue(result["chain"]["is_valid"])
        self.assertEqual(len(result["blocks"]), result["chain"]["height"])
        self.assertIn("Miner", {w["name"] for w in result["wallets"]})

    def test_block_detail_has_merkle_levels_ending_in_root(self) -> None:
        _, payload = self._req("/api/block?index=3")
        block = payload["result"]
        self.assertEqual(block["merkle_levels"][-1], [block["merkle_root"]])
        self.assertEqual(len(block["header_hex"]), 88 * 2)

    def test_merkle_proof_verifies(self) -> None:
        _, payload = self._req("/api/proof?block=3&tx=1")
        proof = payload["result"]
        self.assertTrue(proof["verified"])
        self.assertEqual(proof["step_count"], len(proof["steps"]))

    def test_trace_replays_the_winning_nonce(self) -> None:
        _, payload = self._req("/api/trace?index=5")
        trace = payload["result"]
        last = trace["attempts"][-1]
        self.assertTrue(last["ok"])
        self.assertEqual(last["nonce"], trace["block"]["nonce"])
        self.assertEqual(last["hash"], trace["block"]["hash"])
        self.assertFalse(any(a["ok"] for a in trace["attempts"][:-1]))
        self.assertEqual(len(trace["hash_sample"]["avalanche_bits"]), 256)

    def test_send_then_mine_includes_tx_and_emits_events(self) -> None:
        events = self.state.events.subscribe()
        try:
            status, payload = self._req("/api/tx", {"from": "Alice", "to": "Bob", "amount": 3, "fee": 1})
            self.assertEqual(status, 200, payload)
            tx_id = payload["result"]["tx"]["tx_id"]
            status, payload = self._req("/api/mine", {})
            self.assertEqual(status, 200, payload)
            mined_ids = [tx["tx_id"] for tx in payload["result"]["block"]["transactions"]]
            self.assertIn(tx_id, mined_ids)
            kinds = [events.get(timeout=5)[0], events.get(timeout=5)[0]]
            self.assertEqual(kinds, ["tx_submitted", "block_mined"])
        finally:
            self.state.events.unsubscribe(events)

    def test_tamper_reports_cascade_without_touching_the_ledger(self) -> None:
        status, payload = self._req("/api/tamper", {"block": 2, "tx": 1})
        self.assertEqual(status, 200, payload)
        report = payload["result"]
        self.assertFalse(report["merkle_root_matches_header"])
        self.assertIn(3, report["downstream_broken"])
        self.assertTrue(report["chain_still_valid"])

    def test_bad_requests_are_400_json(self) -> None:
        for path, body in [
            ("/api/tx", {"from": "Nobody", "to": "Bob", "amount": 1}),
            ("/api/tx", {"from": "Alice", "to": "Bob", "amount": 10 ** 9}),
            ("/api/tamper", {"block": 999}),
        ]:
            status, payload = self._req(path, body)
            self.assertEqual(status, 400, path)
            self.assertFalse(payload["ok"])
        status, payload = self._req("/api/tx", raw=b"not json")
        self.assertEqual(status, 400)
        status, payload = self._req("/api/block?index=abc")
        self.assertEqual(status, 400)

    def test_static_index_served_and_traversal_blocked(self) -> None:
        with urllib.request.urlopen(self.base + "/", timeout=5) as resp:
            self.assertIn(b"Blockchain-Lite", resp.read())
        # Raw socket so the client cannot normalise the "..".
        with socket.create_connection(self.server.server_address, timeout=5) as sock:
            sock.sendall(b"GET /static/../bridge.py HTTP/1.0\r\n\r\n")
            head = sock.recv(64)
        self.assertIn(b"404", head)

    def test_consensus_reports_target_and_thresholds(self) -> None:
        _, payload = self._req("/api/state")
        cons = payload["result"]["consensus"]
        self.assertTrue(cons["retargeting"])
        self.assertAlmostEqual(cons["target_block_time"], 10.0)
        self.assertLess(cons["fast_below"], cons["target_block_time"])
        self.assertGreater(cons["slow_above"], cons["target_block_time"])

    def test_autominer_toggles(self) -> None:
        status, payload = self._req("/api/autominer", {"on": True})
        self.assertEqual(status, 200, payload)
        self.assertTrue(payload["result"]["running"])
        status, payload = self._req("/api/autominer", {"on": False})
        self.assertFalse(payload["result"]["running"])
        self.state.autominer._thread.join(timeout=30)
        self.assertTrue(self.state.ledger.validate_full_chain(force=True).is_valid)

    def test_sse_stream_delivers_events(self) -> None:
        with socket.create_connection(self.server.server_address, timeout=5) as sock:
            sock.sendall(b"GET /events HTTP/1.0\r\n\r\n")
            buf = b""
            while b": connected" not in buf:
                buf += sock.recv(1024)
            self.state.events.publish("block_mined", {"probe": 1})
            while b"event: block_mined" not in buf:
                buf += sock.recv(1024)
        self.assertIn(b'"probe": 1', buf)

    def test_unlock_checks_the_passcode(self) -> None:
        status, payload = self._req("/api/unlock", {"passcode": "87654321"})
        self.assertEqual(status, 200, payload)
        self.assertFalse(payload["result"]["granted"])
        self.assertEqual(payload["result"]["attempts_left"], MAX_ATTEMPTS - 1)
        status, payload = self._req("/api/unlock", {"passcode": "12345678"})
        self.assertTrue(payload["result"]["granted"])
        for bad in ["1234", "abcdefgh", 12345678, None]:
            status, payload = self._req("/api/unlock", {"passcode": bad})
            self.assertEqual(status, 400, bad)
            self.assertFalse(payload["ok"])


class TestLedgerCopies(unittest.TestCase):
    """Everyone holds a ledger copy; the network check repairs tampered copies from the majority."""

    def setUp(self) -> None:
        self.state = build_state(fast_hash=True)
        self.net = self.state.network

    def _status(self) -> dict:
        return {p["name"]: p for p in self.net.view()["peers"]}

    def test_every_wallet_has_a_synced_copy(self) -> None:
        peers = self._status()
        self.assertEqual(set(peers), set(self.state.wallets))
        self.assertTrue(all(p["status"] == "ok" for p in peers.values()))
        self.state.mine(with_trace=False)
        heights = {p["height"] for p in self._status().values()}
        self.assertEqual(heights, {self.state.ledger.height})

    def test_tampered_copy_is_flagged_then_restored_from_majority(self) -> None:
        events = self.state.events.subscribe()
        report = self.state.tamper_copy({"name": "Grace", "block": 5, "tx": 1, "amount": 999})
        self.assertFalse(report["merkle_root_matches_header"])
        self.assertEqual(self._status()["Grace"]["status"], "tampered")
        self.assertNotEqual(self.net.blocks_of("Grace")[5].transactions[1].outputs[0].amount, report["old_amount"])

        summary = self.net.audit()
        self.assertEqual([r["name"] for r in summary["repaired"]], ["Grace"])
        self.assertEqual(summary["majority_size"], len(self.state.wallets) - 1)
        self.assertEqual(self._status()["Grace"]["status"], "ok")
        self.assertIs(self.net.blocks_of("Grace")[5], self.state.ledger.blocks[5])

        kinds = []
        while not events.empty():
            kinds.append(events.get_nowait()[0])
        self.assertEqual(kinds, ["copy_tampered", "network_audit", "ledger_repaired"])
        self.assertEqual(self.net.audit()["repaired"], [])  # nothing left to fix

    def test_tampered_copy_keeps_syncing_new_blocks_until_repaired(self) -> None:
        self.state.tamper_copy({"name": "Bob", "block": 3, "tx": 0, "amount": 5000})
        self.state.mine(with_trace=False)
        self.assertEqual(len(self.net.blocks_of("Bob")), self.state.ledger.height)
        self.net.audit()
        self.assertEqual(self.net.blocks_of("Bob"), list(self.state.ledger.blocks))

    def test_bad_tamper_requests_are_refused(self) -> None:
        for body in [
            {"name": "Nobody", "block": 2, "tx": 0, "amount": 5},
            {"name": "Alice", "block": 0, "tx": 0, "amount": 5},
            {"name": "Alice", "block": 2, "tx": 99, "amount": 5},
            {"name": "Alice", "block": 2, "tx": 0, "amount": 0},
        ]:
            with self.assertRaises(ValidationError, msg=body):
                self.state.tamper_copy(body)

    def test_new_person_gets_wallet_copy_and_funding(self) -> None:
        result = self.state.add_person({"name": "Ravi", "fund": 20})
        self.assertIsNone(result["fund_error"])
        self.assertIn("Ravi", self._status())
        self.assertEqual(self._status()["Ravi"]["height"], self.state.ledger.height)
        self.state.mine(with_trace=False)
        balances = {w["name"]: w["balance"] for w in self.state.wallet_list()}
        self.assertEqual(balances["Ravi"], 20)
        # Ravi now votes in the network check too.
        self.assertEqual(self.net.audit()["copies"], len(self.state.wallets))

    def test_person_names_are_validated(self) -> None:
        for name in ["", "   ", "alice", "x" * 21, "<script>"]:
            with self.assertRaises(ValidationError, msg=name):
                self.state.add_person({"name": name})


class TestBridgeRetargeting(unittest.TestCase):
    """Blocks mined faster than the target raise difficulty; slower ones lower it."""

    def test_fast_blocks_raise_difficulty_and_announce_it(self) -> None:
        state = build_state(fast_hash=True, block_time=10.0, retarget_interval=4)
        start = state.ledger.tip.difficulty
        self.assertEqual(state.consensus()["next_difficulty"], start)  # paced history is neutral
        events = state.events.subscribe()
        for _ in range(6):  # all within a second or two: far below the 7.5 s threshold
            state.mine(with_trace=False)
        self.assertGreater(state.ledger.calculate_next_difficulty(), start)
        kinds = []
        while not events.empty():
            kinds.append(events.get_nowait()[0])
        self.assertIn("difficulty_changed", kinds)
        self.assertTrue(state.ledger.validate_full_chain(force=True).is_valid)

    def test_slow_blocks_lower_difficulty(self) -> None:
        state = build_state(fast_hash=True, block_time=10.0, retarget_interval=4)
        ledger = state.ledger
        miner = state.wallets["Miner"].address
        ts = ledger.tip.timestamp
        while ledger.height % 4 != 0:  # line up with a retarget boundary
            ts += 10
            ledger.mine_pending_transactions(miner_address=miner, timestamp=ts)
        before = ledger.calculate_next_difficulty()
        for _ in range(4):
            ts += 60  # one block a minute against a 10 s target
            ledger.mine_pending_transactions(miner_address=miner, timestamp=ts)
        self.assertEqual(ledger.calculate_next_difficulty(), max(1, before - 1))

    def test_fixed_difficulty_when_retargeting_off(self) -> None:
        state = build_state(fast_hash=True, retarget_interval=0)
        for _ in range(5):
            state.mine(with_trace=False)
        self.assertEqual({b.difficulty for b in state.ledger.blocks}, {4})
        self.assertFalse(state.consensus()["retargeting"])



class TestPasscodeGate(unittest.TestCase):
    def setUp(self) -> None:
        self.now = 100.0
        self.gate = PasscodeGate("24681357", clock=lambda: self.now)

    def test_right_code_resets_the_failure_count(self) -> None:
        self.assertEqual(self.gate.check("00000000")["attempts_left"], MAX_ATTEMPTS - 1)
        self.assertTrue(self.gate.check("24681357")["granted"])
        self.assertEqual(self.gate.check("00000000")["attempts_left"], MAX_ATTEMPTS - 1)

    def test_too_many_wrong_codes_lock_the_gate(self) -> None:
        for _ in range(MAX_ATTEMPTS - 1):
            self.gate.check("00000000")
        result = self.gate.check("00000000")
        self.assertEqual(result["locked_for"], LOCKOUT_SECONDS)
        # Even the right code is refused while locked.
        self.now += 10
        locked = self.gate.check("24681357")
        self.assertFalse(locked["granted"])
        self.assertAlmostEqual(locked["locked_for"], LOCKOUT_SECONDS - 10)
        self.now += LOCKOUT_SECONDS
        self.assertTrue(self.gate.check("24681357")["granted"])

    def test_passcode_must_be_eight_digits(self) -> None:
        for bad in ["1234567", "123456789", "1234abcd", ""]:
            with self.assertRaises(ValidationError):
                PasscodeGate(bad)
        self.assertFalse(self.gate.is_default)
        self.assertTrue(PasscodeGate().is_default)


if __name__ == "__main__":
    unittest.main()
