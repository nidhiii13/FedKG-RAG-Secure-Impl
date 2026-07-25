#!/usr/bin/env python3
"""Production-facing wrapper for N-party private indexed MPC retrieval.

This keeps the older implementation files intact while exposing the intended
methodology directly:

private semantic bucket lookup -> private entity-index lookup -> MPC traversal
and support aggregation -> MPC top-k -> controlled evidence reveal.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
RUNNER = SCRIPT_DIR / "run_source_oram_limb_private_semantic_metaqa_batch.py"


def _has_flag(args: list[str], flag: str) -> bool:
    prefix = f"{flag}="
    return any(arg == flag or arg.startswith(prefix) for arg in args)


def main() -> int:
    args = list(sys.argv[1:])
    defaults = []
    if not _has_flag(args, "--ranking-backend"):
        defaults.extend(["--ranking-backend", "mpc"])
    if not _has_flag(args, "--production-secure"):
        defaults.append("--production-secure")
    if not _has_flag(args, "--skip-compile-if-present"):
        defaults.append("--skip-compile-if-present")
    if not _has_flag(args, "--mp-spdz-protocol"):
        defaults.extend(["--mp-spdz-protocol", "semi"])

    command = [sys.executable, str(RUNNER), *args, *defaults]
    return subprocess.run(command, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
