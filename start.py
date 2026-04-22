#!/usr/bin/env python3
"""Workspace-level single start entrypoint."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


if __name__ == "__main__":
    root = Path(__file__).resolve().parent
    target = root / "adaptive_zta" / "start.py"
    raise SystemExit(subprocess.call([sys.executable, str(target)], cwd=str(root)))
