"""
Render a block's forge trace to an MP4 with Manim.

Used two ways:
- by the bridge (`python3 -m web.bridge --render`): `RenderQueue` renders each
  newly mined block in a background thread and reports the file name;
- by hand, against a running bridge:
      python3 -m viz.render --block 10              (fetches /api/trace?index=10)
      python3 -m viz.render --trace trace.json      (a saved trace)

Output: web/static/renders/block_<index>.mp4, served by the bridge at /renders/.
Needs `pip install manim` (and its system libraries: cairo, pango, ffmpeg).
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import logging
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("blockchain_lite.viz")

SCENES_FILE = Path(__file__).resolve().parent / "scenes.py"
DEFAULT_OUT_DIR = Path(__file__).resolve().parent.parent / "web" / "static" / "renders"


def manim_available() -> bool:
    return importlib.util.find_spec("manim") is not None


def render_trace(
    trace: Dict[str, Any],
    out_dir: Path = DEFAULT_OUT_DIR,
    quality: str = "l",
    scene: str = "BlockForgeScene",
) -> Path:
    """Render `scene` for `trace` and return the path of the finished MP4."""
    index = int(trace["block"]["index"])
    out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="blt-render-") as tmp:
        tmp_path = Path(tmp)
        trace_file = tmp_path / "trace.json"
        trace_file.write_text(json.dumps(trace), encoding="utf-8")
        cmd = [
            sys.executable, "-m", "manim", f"-q{quality}", "--disable_caching",
            "--media_dir", str(tmp_path / "media"), "-o", f"block_{index}",
            str(SCENES_FILE), scene,
        ]
        env = dict(os.environ, BLT_TRACE=str(trace_file))
        proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(f"manim failed ({proc.returncode}): {proc.stderr[-2000:]}")
        produced = sorted((tmp_path / "media").rglob(f"block_{index}.mp4"))
        if not produced:
            raise RuntimeError("manim finished but produced no MP4")
        target = out_dir / f"block_{index}.mp4"
        shutil.move(str(produced[0]), target)
        return target


class RenderQueue:
    """One background worker that renders traces in order (Manim is CPU-heavy)."""

    def __init__(self, out_dir: Path = DEFAULT_OUT_DIR, quality: str = "l") -> None:
        self.out_dir = out_dir
        self.quality = quality
        self.available = manim_available()
        self._jobs: "queue.Queue[tuple]" = queue.Queue()
        if self.available:
            threading.Thread(target=self._run, name="manim-render", daemon=True).start()

    def submit(self, trace: Dict[str, Any], on_done: Optional[Callable[[List[str]], None]] = None) -> None:
        if self.available:
            self._jobs.put((trace, on_done))

    def _run(self) -> None:
        while True:
            trace, on_done = self._jobs.get()
            try:
                path = render_trace(trace, self.out_dir, self.quality)
                logger.info("Rendered %s", path.name)
                if on_done is not None:
                    on_done([path.name])
            except Exception:  # keep the worker alive whatever one render does
                logger.exception("Render of block #%s failed", trace.get("block", {}).get("index"))


def _fetch_trace(bridge: str, block: int) -> Dict[str, Any]:
    with urllib.request.urlopen(f"{bridge.rstrip('/')}/api/trace?index={block}", timeout=30) as resp:
        payload = json.load(resp)
    if not payload.get("ok"):
        raise SystemExit(f"bridge error: {payload.get('error')}")
    return payload["result"]


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Render a Blockchain-Lite block with Manim")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--block", type=int, help="block index to fetch from a running bridge")
    src.add_argument("--trace", type=Path, help="JSON trace saved from /api/trace")
    parser.add_argument("--bridge", default="http://127.0.0.1:8080")
    parser.add_argument("--quality", default="l", choices=["l", "m", "h", "k"])
    parser.add_argument("--scene", default="BlockForgeScene")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT_DIR)
    args = parser.parse_args(argv)

    if not manim_available():
        raise SystemExit("Manim is not installed: pip install manim")
    trace = json.loads(args.trace.read_text(encoding="utf-8")) if args.trace else _fetch_trace(args.bridge, args.block)
    path = render_trace(trace, args.out, args.quality, args.scene)
    print(path)


if __name__ == "__main__":
    main()
