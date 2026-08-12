from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from .config import PublicConfig
from .sharing import SERVER_COUNT, reconstruct


LINE = re.compile(r"DORAM_SHARE\s+(\d+)\s+([0-3])\s+([0-2])\s+(-?\d+)")
FIELD_NAMES = ("valid", "left_evidence", "right_evidence", "score")


def decode_logs(config: PublicConfig, logs: list[str | Path]) -> list[dict[str, int]]:
    if len(logs) != SERVER_COUNT:
        raise ValueError("the client must receive exactly one output log from each server")
    shares: dict[tuple[int, int], dict[int, int]] = {}
    for expected_server, path in enumerate(logs):
        for match in LINE.finditer(Path(path).read_text(encoding="utf-8")):
            rank, field, claimed_server, value = map(int, match.groups())
            if claimed_server != expected_server:
                raise ValueError(f"output log {path} contains a share for another server")
            if rank not in range(config.top_k):
                raise ValueError("output contains an out-of-range result rank")
            key = (rank, field)
            if expected_server in shares.setdefault(key, {}):
                raise ValueError("duplicate output share")
            shares[key][expected_server] = value % config.field_prime

    expected = {(rank, field) for rank in range(config.top_k) for field in range(4)}
    if set(shares) != expected or any(set(value) != set(range(3)) for value in shares.values()):
        raise ValueError("missing or unexpected output shares")
    results = []
    for rank in range(config.top_k):
        row = {
            FIELD_NAMES[field]: reconstruct(
                (shares[(rank, field)][server] for server in range(3)),
                modulus=config.field_prime,
            )
            for field in range(4)
        }
        if row["valid"] not in (0, 1):
            raise ValueError("MPC returned a non-boolean validity value")
        if not row["valid"] and any(row[name] for name in FIELD_NAMES[1:]):
            raise ValueError("invalid MPC result has non-zero payload")
        results.append(row)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Reconstruct DORAM results at the query client")
    parser.add_argument("--config", required=True)
    parser.add_argument("--server-log", action="append", required=True)
    args = parser.parse_args()
    results = decode_logs(PublicConfig.load(args.config), args.server_log)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
