#!/usr/bin/env python3
"""
Blockchain-Lite Terminal Console Entry Point.

Usage:
    python3 run_terminal.py
    python3 run_terminal.py --fast-hash
    python3 run_terminal.py --demo
    python3 run_terminal.py --status
    python3 run_terminal.py --benchmark
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure package root is in Python path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from blockchain_lite.cli.terminal import main

if __name__ == "__main__":
    main()
