---
tags: [module, tooling]
files: [tools/bundle.py, blockchain_lite_complete.py]
---
# mod — tools/bundle

`tools/bundle.py` concatenates the package modules in dependency order (`ORDERED_MODULES`), resolves intra-package imports, and embeds source/tests/docs as base64 so the single file can `--unpack` the project. Output: `blockchain_lite_complete.py` (~6.1k lines) with `--demo`, `--test`, `--unpack`.

> [!tip] Regenerated on 2026-10-28 (was ~280 lines stale). Docs are embedded too, so re-run `python tools/bundle.py` after any source **or doc** change. See [[Review Findings]].

Back to [[Code Map]].
