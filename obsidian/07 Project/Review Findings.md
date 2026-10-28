---
tags: [project, todo, review]
---
# Review Findings

What I noticed while reading the whole repo (2026-10-28). Overall the code is in good shape: 126 tests pass, clear module split, strong docs. These are housekeeping items:

- [x] **`SECURITY.md` is a placeholder** — *fixed: full threat model written (defences table + 7 limitations).* — it only contains the text "IF You Want", but the README links it as the threat model. Move/copy `docs/HLD_and_Interfaces.md` §6 + [[Known Limitations]] into it.
- [x] **Stray text in `docs/Project_Guide.md`** — *fixed.* — the heading reads `## Contents YES ME :`. Should be `## Contents`.
- [x] **Stale bundle** — *fixed: regenerated; its `--test` runs 134 tests OK.* — `python tools/bundle.py` changes ~280 lines of `blockchain_lite_complete.py`. Regenerate before submission. ([[mod - tools bundle]])
- [ ] **Dead code** — `core/` is an unused prototype; `network/web_dashboard.py` (1.7k lines) survives only for `test_phase10`. Decide: delete or move to `archive/`. ([[Legacy Code]])
- [ ] **Python version mismatch** — `pyproject.toml` says `>=3.11`, Dockerfile uses 3.11, local machine runs 3.9.6. Works today, but `pip install .` would refuse on 3.9.
- [x] **Test count drift** — *fixed in README (14 modules, 126 tests); CHANGELOG/pyproject numbers are dated measurements, kept as history.* — README says "`tests/` (12 modules)", Project Guide says 14 modules / 126 tests; the coverage comment in `pyproject.toml` mentions 101 tests. Align numbers.
- [ ] **Manim path untested** — run `--render` once on a machine with Manim before the viva if you plan to show it.

Related: [[Timeline and History]].
