#!/usr/bin/env python3
"""Reconstruct two MPC runs' outputs from their party logs and compare them.

Why this exists
---------------
Every optimization in this repository claims to be semantically a no-op, and the
only way to check that is to reconstruct the actual outputs of both circuits and
compare. The circuit emits 3-of-3 additive shares, one line per party, so a
single party's log tells you nothing -- the shares are uniformly random. Summing
all three modulo the prime recovers the value.

This was written inline four times during one session before being made a script,
which is exactly the sort of thing that ends up subtly different each time.

Usage
-----
    python3 scripts/compare_mpc_outputs.py --logs <MP-SPDZ>/logs \\
        --baseline mpc-webqsp-20-u20 --candidate mpc-webqsp-20-f20

Exits non-zero when the two disagree, so it can gate a regression run.
"""

from __future__ import annotations

import argparse
import re
from collections import defaultdict
from pathlib import Path


FIELD_PRIME = (1 << 127) - 1
LINE = re.compile(r"DORAM_BATCH_SHARE (\d+) (\d+) (\d+) (\d+) (-?\d+)")


def reconstruct(logs: Path, label: str, prime: int = FIELD_PRIME):
    """Sum each output's three party shares. Returns {(query, rank, field): value}.

    Values missing a party are dropped rather than reconstructed from two shares,
    because two of three shares carry no information -- a partial reconstruction
    would be a plausible-looking wrong answer.
    """

    shares: dict[tuple[int, int, int], dict[int, int]] = defaultdict(dict)
    files = sorted(logs.glob(f"{label}-*"))
    for path in files:
        for line in path.read_text(errors="ignore").splitlines():
            found = LINE.match(line.strip())
            if found:
                query, rank, field, server, value = (
                    int(part) for part in found.groups()
                )
                shares[(query, rank, field)][server] = value % prime
    complete = {
        key: sum(parts.values()) % prime
        for key, parts in shares.items()
        if len(parts) == 3
    }
    return complete, len(files), len(shares) - len(complete)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--logs", type=Path, required=True)
    parser.add_argument("--baseline", required=True, help="log label of the reference run")
    parser.add_argument("--candidate", required=True, help="log label of the new run")
    parser.add_argument("--prime", type=int, default=FIELD_PRIME)
    args = parser.parse_args()

    base, base_files, base_partial = reconstruct(args.logs, args.baseline, args.prime)
    cand, cand_files, cand_partial = reconstruct(args.logs, args.candidate, args.prime)

    for name, values, files, partial in (
        (args.baseline, base, base_files, base_partial),
        (args.candidate, cand, cand_files, cand_partial),
    ):
        print(f"{name:34s} {len(values):4d} values from {files} party logs"
              + (f"  ({partial} incomplete, dropped)" if partial else ""))

    if not base or not cand:
        print("\nFAIL: one side reconstructed nothing -- check the log labels")
        return 2

    keys = sorted(set(base) | set(cand))
    differing = [key for key in keys if base.get(key) != cand.get(key)]
    if differing:
        print(f"\nDIFFER on {len(differing)} of {len(keys)} outputs:")
        for key in differing[:10]:
            print(f"  (query {key[0]}, rank {key[1]}, field {key[2]}): "
                  f"baseline={base.get(key)} candidate={cand.get(key)}")
        return 1
    print(f"\nIDENTICAL on all {len(keys)} outputs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
