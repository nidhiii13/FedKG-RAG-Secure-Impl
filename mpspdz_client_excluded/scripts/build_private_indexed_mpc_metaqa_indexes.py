#!/usr/bin/env python3
"""Build indexes for the N-party private indexed MPC retrieval path."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
BUILDER = SCRIPT_DIR / "build_metaqa_oram_limb_private_semantic_indexes.py"


def main() -> int:
    command = [sys.executable, str(BUILDER), *sys.argv[1:]]
    return subprocess.run(command, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
