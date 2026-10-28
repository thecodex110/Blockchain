---
tags: [overview, howto]
---
# How to Run

Back to [[Home]]. Everything runs with plain `python3` — no `pip install` needed (except optional Manim).

## Terminal
```bash
python3 run_terminal.py              # interactive console
python3 run_terminal.py --fast-hash  # hashlib backend, much faster
python3 run_terminal.py --demo       # 6-stage viva demo
python3 run_terminal.py --status     # chain status only
python3 -m blockchain_lite.cli.demo  # demo directly (--rsa-bits N)
```
→ [[mod - cli]], [[Six-Stage Demo]]

## Web app
```bash
python3 -m web.bridge                                   # http://127.0.0.1:8080
python3 -m web.bridge --block-time 10 --retarget-interval 4 --auto-mine
python3 -m web.bridge --retarget-interval 0             # fixed difficulty
python3 -m web.bridge --passcode 24681357               # default 12345678
python3 -m web.bridge --bit-level-hash                  # use from-scratch SHA-256
python3 -m web.bridge --render                          # Manim videos (pip install manim)
python3 -m viz.render --block 10                        # render one block by hand
```
→ [[mod - web bridge]], [[mod - web frontend]], [[mod - viz manim]]

## Tests
```bash
python3 run_tests.py
python3 -m unittest -v tests.test_attack_scenarios
```
→ [[Test Suite]]

## Single-file build
```bash
python blockchain_lite_complete.py            # console
python blockchain_lite_complete.py --demo
python blockchain_lite_complete.py --test
python blockchain_lite_complete.py --unpack ./out
python tools/bundle.py                        # regenerate
```
→ [[mod - tools bundle]]

## Docker
```bash
docker compose run --rm terminal                       # console (--fast-hash)
docker compose --profile demo run --rm cli-demo
docker compose --profile test run --rm test-suite
```
Image: `python:3.11-slim`, non-root `appuser`, runs `run_tests.py` during build.

## Demo chain
Genesis gives **20 named wallets** 300–500 coins each (9,200 total). Then **10 blocks are pre-mined**, each with 8 signed transfers + a coinbase. The **Miner** wallet starts at 0 and earns every reward. Keys are random each run, so hashes differ every start.
