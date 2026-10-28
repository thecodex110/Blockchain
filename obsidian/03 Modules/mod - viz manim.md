---
tags: [module, viz]
files: [viz/scenes.py, viz/render.py, viz/requirements.txt]
---
# mod — viz (Manim)

Optional MP4 animations of how a block is built. Needs `pip install manim` (+ cairo, pango, ffmpeg).

- `scenes.py` — `ForgeMixin` with `step_collect`, `step_hash`, `step_merkle`, `step_pow`, `step_append`; scenes `CollectTxScene`, `HashScene`, `MerkleScene`, `PoWScene`, `AppendScene`, `BlockForgeScene` (all five). Reads a forge trace JSON.
- `render.py` — `render_trace`, `RenderQueue` (background thread used by `web.bridge --render`), CLI `python3 -m viz.render --block N` or `--trace file.json`. Output → `web/static/renders/block_<i>.mp4` (gitignored), served at `/renders/`.

> [!warning] Untested on the dev machine (Manim not installed) — see [[Known Limitations]].

Back to [[Code Map]].
