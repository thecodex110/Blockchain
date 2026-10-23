"""
Manim scenes that replay how one block was built, from a real forge trace.

The trace is the JSON returned by the bridge's `/api/trace?index=N` (or by
`POST /api/mine`). Point `BLT_TRACE` at a file holding it, then render:

    BLT_TRACE=trace.json manim -ql viz/scenes.py BlockForgeScene

`python3 -m viz.render` does this for you. Scenes:
CollectTxScene, HashScene, MerkleScene, PoWScene, AppendScene, and
BlockForgeScene (all five in a row).
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List

from manim import (
    DOWN,
    LEFT,
    RIGHT,
    UP,
    Arrow,
    Circle,
    Create,
    FadeIn,
    FadeOut,
    GrowArrow,
    LaggedStart,
    Line,
    RoundedRectangle,
    Scene,
    Text,
    Transform,
    VGroup,
    Write,
    config,
)

# Same palette as the web frontend.
GROUND = "#EFE9DF"
CARD = "#F8F4EC"
INK = "#12343B"
MUTED = "#5E6E6A"
TEAL_900 = "#10606F"
TEAL_400 = "#4FB8B4"
TEAL_200 = "#98D8D0"
TEAL_50 = "#E2F4F0"
SAND = "#E8DDCF"
NIGHT = "#0C1A1D"
CREAM = "#FAF6F0"

MONO = "Menlo"
SERIF = "Georgia"

config.background_color = GROUND


def load_trace() -> Dict[str, Any]:
    path = os.environ.get("BLT_TRACE")
    if not path:
        raise RuntimeError("Set BLT_TRACE to a JSON trace from /api/trace?index=N")
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def short(h: str, a: int = 8, b: int = 4) -> str:
    return f"{h[:a]}…{h[-b:]}" if len(h) > a + b else h


def pill(label: str, fill: str = CARD, color: str = INK, width: float = 3.6, height: float = 0.5,
         font: str = MONO, size: int = 20) -> VGroup:
    box = RoundedRectangle(corner_radius=height / 2, width=width, height=height,
                           fill_color=fill, fill_opacity=1, stroke_width=0)
    text = Text(label, font=font, color=color, font_size=size)
    if text.width > width - 0.3:
        text.scale_to_fit_width(width - 0.3)
    return VGroup(box, text.move_to(box))


def title(text: str) -> Text:
    return Text(text, font=SERIF, color=INK, font_size=44, weight="BOLD").to_edge(UP, buff=0.45)


class ForgeMixin:
    """Each step is a method so BlockForgeScene can chain them."""

    trace: Dict[str, Any]

    def fade_all(self) -> None:
        if self.mobjects:  # type: ignore[attr-defined]
            self.play(*[FadeOut(m) for m in self.mobjects], run_time=0.5)  # type: ignore[attr-defined]

    # 1. Mempool -> candidate block -------------------------------------------------
    def step_collect(self) -> None:
        txs: List[Dict[str, Any]] = self.trace["block"]["transactions"][:6]
        head = title(f"Gathering transactions for block #{self.trace['block']['index']}")
        self.play(Write(head))
        rows = VGroup(*[
            pill(
                f"{tx['tx_id'][:8]}  {'coinbase' if tx['type'] == 'coinbase' else tx['from']} → "
                f"{tx['outputs'][0]['to']}  {tx['outputs'][0]['amount']}",
                fill=TEAL_900 if tx["type"] == "coinbase" else CARD,
                color=CREAM if tx["type"] == "coinbase" else INK,
                width=5.2,
            )
            for tx in txs
        ]).arrange(DOWN, buff=0.18).to_edge(LEFT, buff=0.8).shift(DOWN * 0.3)
        block = RoundedRectangle(corner_radius=0.4, width=5.8, height=4.6, stroke_color=TEAL_400,
                                 stroke_width=4, fill_color=CARD, fill_opacity=1).to_edge(RIGHT, buff=0.8).shift(DOWN * 0.3)
        label = Text(f"Block #{self.trace['block']['index']}", font=SERIF, color=INK, font_size=34)
        label.next_to(block.get_top(), DOWN, buff=0.3)
        self.play(LaggedStart(*[FadeIn(r, shift=RIGHT * 0.4) for r in rows], lag_ratio=0.15))
        self.play(Create(block), Write(label))
        targets = rows.copy().scale(0.62).arrange(DOWN, buff=0.08).next_to(label, DOWN, buff=0.25)
        self.play(LaggedStart(*[Transform(r, t) for r, t in zip(rows, targets)], lag_ratio=0.12), run_time=2)
        self.wait(0.8)

    # 2. Hashing ------------------------------------------------------------------
    def step_hash(self) -> None:
        hs = self.trace["hash_sample"]
        head = title("Hashing a transaction with SHA-256")
        self.play(Write(head))
        raw = pill(hs["tx_bytes_hex"][:28] + "…", width=4.6, size=18).shift(LEFT * 4.3 + UP * 0.6)
        orb = VGroup(Circle(radius=1.15, fill_color=NIGHT, fill_opacity=1, stroke_color=TEAL_200, stroke_width=6),
                     Text("SHA-256", font=MONO, color=TEAL_50, font_size=26)).shift(UP * 0.6)
        out = pill(short(hs["tx_id"], 12, 6), fill=TEAL_50, color=TEAL_900, width=4.4, size=18).shift(RIGHT * 4.3 + UP * 0.6)
        a1 = Arrow(raw.get_right(), orb.get_left(), color=TEAL_400, buff=0.15)
        a2 = Arrow(orb.get_right(), out.get_left(), color=TEAL_400, buff=0.15)
        self.play(FadeIn(raw, shift=RIGHT * 0.3))
        self.play(GrowArrow(a1), FadeIn(orb))
        counter = Text("round 0", font=MONO, color=TEAL_400, font_size=20).next_to(orb, DOWN, buff=0.25)
        self.add(counter)
        for r in range(8, 65, 8):
            self.play(Transform(counter, Text(f"round {r}", font=MONO, color=TEAL_400, font_size=20).move_to(counter)),
                      run_time=0.15)
        self.play(GrowArrow(a2), FadeIn(out, shift=RIGHT * 0.3))
        leaf = pill(f"leaf = H(0x00 ‖ tx_id) = {hs['leaf'][:8]}…", fill=TEAL_400, color=NIGHT, width=6.4, size=20)
        leaf.shift(DOWN * 1.4)
        self.play(FadeIn(leaf, shift=UP * 0.2))
        bits = VGroup(*[
            Circle(radius=0.055, stroke_width=0, fill_opacity=1, fill_color=TEAL_900 if b else SAND)
            for b in hs["avalanche_bits"]
        ]).arrange_in_grid(rows=4, cols=64, buff=0.06).shift(DOWN * 2.6)
        cap = Text(f"1 input bit flipped → {hs['avalanche_flipped']} / 256 output bits flipped",
                   font=MONO, color=MUTED, font_size=18).next_to(bits, DOWN, buff=0.15)
        self.play(LaggedStart(*[FadeIn(b) for b in bits], lag_ratio=0.004), Write(cap), run_time=2)
        self.wait(1)

    # 3. Merkle tree --------------------------------------------------------------
    def step_merkle(self) -> None:
        levels: List[List[str]] = self.trace["block"]["merkle_levels"]
        head = title("Building the Merkle tree")
        self.play(Write(head))
        top = len(levels) - 1
        rows: List[VGroup] = []
        for depth, level in enumerate(levels):
            y = -2.9 + depth * (5.0 / max(top, 1))
            fill = TEAL_900 if depth == top else (CARD if depth == 0 else TEAL_200)
            color = CREAM if depth == top else INK
            width = min(1.35, 12.5 / max(len(level), 1) - 0.12)
            row = VGroup(*[pill(h[:8], fill=fill, color=color, width=width, height=0.46, size=16) for h in level])
            row.arrange(RIGHT, buff=0.12).move_to([0, y, 0])
            rows.append(row)
        self.play(LaggedStart(*[FadeIn(n, shift=UP * 0.2) for n in rows[0]], lag_ratio=0.08))
        for depth in range(1, len(rows)):
            lines = VGroup()
            for i, parent in enumerate(rows[depth]):
                for child_i in (2 * i, 2 * i + 1):
                    child = rows[depth - 1][min(child_i, len(rows[depth - 1]) - 1)]
                    lines.add(Line(child.get_top(), parent.get_bottom(), color=TEAL_400, stroke_width=2))
            self.play(Create(lines), LaggedStart(*[FadeIn(p, scale=0.8) for p in rows[depth]], lag_ratio=0.1), run_time=1)
        root_note = Text(f"root {short(levels[-1][0], 10, 6)}", font=MONO, color=TEAL_900, font_size=22)
        root_note.next_to(rows[-1], RIGHT, buff=0.4)
        self.play(Write(root_note))
        self.wait(1)

    # 4. Proof-of-Work ------------------------------------------------------------
    def step_pow(self) -> None:
        b = self.trace["block"]
        attempts = self.trace["attempts"]
        head = title(f"Proof-of-Work: first {self.trace['target_bits']} bits must be zero")
        self.play(Write(head))
        fields = VGroup(
            pill(str(b["index"]), fill="#CFD8C4", width=0.8),
            pill(f"prev {b['previous_hash'][:8]}", fill=TEAL_200, width=2.8),
            pill(f"merkle {b['merkle_root'][:8]}", fill=TEAL_400, width=2.8),
            pill("time", fill="#CFD8C4", width=1.1),
            pill(f"D={b['difficulty']}", fill=SAND, width=1.1),
        ).arrange(RIGHT, buff=0.1)
        nonce = pill("n=0", fill=TEAL_900, color=CREAM, width=1.6)
        header = VGroup(fields, nonce).arrange(RIGHT, buff=0.1).next_to(head, DOWN, buff=0.5)
        self.play(FadeIn(header))
        shown = attempts[-10:]
        y0 = 0.6
        prev_row = None
        for i, a in enumerate(shown):
            self.play(Transform(nonce, pill(f"n={a['nonce']}", fill=TEAL_900, color=CREAM, width=1.6).move_to(nonce)),
                      run_time=0.12)
            row = pill(f"n={a['nonce']:>3}   {a['hash'][:20]}…   {'FOUND' if a['ok'] else '×'}",
                       fill=TEAL_900 if a["ok"] else CARD, color=CREAM if a["ok"] else MUTED, width=8.4, size=20)
            row.move_to([0, y0 - 0.48 * (i % 7), 0])
            if i and i % 7 == 0 and prev_row is not None:
                self.play(*[FadeOut(m) for m in self.mobjects if m not in (head, header, nonce)], run_time=0.2)
            self.play(FadeIn(row, shift=UP * 0.1), run_time=0.18)
            prev_row = row
        total = Text(f"{self.trace['hashes_tried']} hashes tried · expected ≈ {2 ** self.trace['target_bits']}",
                     font=MONO, color=TEAL_900, font_size=22).to_edge(DOWN, buff=0.5)
        self.play(Write(total))
        self.wait(1)

    # 5. Append to chain ----------------------------------------------------------
    def step_append(self) -> None:
        b = self.trace["block"]
        head = title("Linking the block to the chain")
        self.play(Write(head))

        def card(index: int, h: str, prev: str, new: bool = False) -> VGroup:
            box = RoundedRectangle(corner_radius=0.35, width=3.4, height=2.4,
                                   fill_color=TEAL_900 if new else CARD, fill_opacity=1, stroke_width=0)
            color = CREAM if new else INK
            body = VGroup(
                Text(f"#{index}", font=SERIF, color=color, font_size=40),
                Text(f"hash {h[:8]}…", font=MONO, color=color, font_size=18),
                Text(f"prev {prev[:8]}…", font=MONO, color=TEAL_200 if new else MUTED, font_size=18),
            ).arrange(DOWN, aligned_edge=LEFT, buff=0.15).move_to(box)
            return VGroup(box, body)

        old = card(b["index"] - 1, b["previous_hash"], "…").shift(LEFT * 3)
        new = card(b["index"], b["hash"], b["previous_hash"], new=True).shift(RIGHT * 3)
        self.play(FadeIn(old))
        self.play(FadeIn(new, shift=LEFT * 1.5), run_time=1.2)
        link = Arrow(new.get_left(), old.get_right(), color=TEAL_400, buff=0.1, stroke_width=6)
        cap = Text("previous_hash", font=MONO, color=TEAL_900, font_size=20).next_to(link, UP, buff=0.1)
        self.play(GrowArrow(link), Write(cap))
        delta = self.trace["utxo_delta"]
        note = Text(f"UTXO hash map: −{delta['spent']} spent, +{delta['created']} new outputs",
                    font=MONO, color=MUTED, font_size=20).to_edge(DOWN, buff=0.7)
        self.play(Write(note))
        self.wait(1.5)


class _TraceScene(ForgeMixin, Scene):
    def setup(self) -> None:
        self.trace = load_trace()


class CollectTxScene(_TraceScene):
    def construct(self) -> None:
        self.step_collect()


class HashScene(_TraceScene):
    def construct(self) -> None:
        self.step_hash()


class MerkleScene(_TraceScene):
    def construct(self) -> None:
        self.step_merkle()


class PoWScene(_TraceScene):
    def construct(self) -> None:
        self.step_pow()


class AppendScene(_TraceScene):
    def construct(self) -> None:
        self.step_append()


class BlockForgeScene(_TraceScene):
    """All five steps, one after another."""

    def construct(self) -> None:
        for step in (self.step_collect, self.step_hash, self.step_merkle, self.step_pow, self.step_append):
            step()
            self.fade_all()
