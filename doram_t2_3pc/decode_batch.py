from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from .config import PublicConfig
from .decode import FIELD_NAMES
from .sharing import SERVER_COUNT, reconstruct


LINE = re.compile(
    r"DORAM_BATCH_SHARE\s+(\d+)\s+(\d+)\s+([0-3])\s+([0-2])\s+(-?\d+)"
)


def decode_batch_logs(
    config: PublicConfig,
    query_count: int,
    logs: list[str | Path],
) -> list[list[dict[str, int]]]:
    if query_count < 1:
        raise ValueError("query_count must be positive")
    if len(logs) != SERVER_COUNT:
        raise ValueError(
            "the client must receive exactly one output log from each server"
        )

    shares: dict[tuple[int, int, int], dict[int, int]] = {}
    for expected_server, path in enumerate(logs):
        for match in LINE.finditer(Path(path).read_text(encoding="utf-8")):
            query, rank, field, claimed_server, value = map(int, match.groups())
            if claimed_server != expected_server:
                raise ValueError(f"output log {path} contains a share for another server")
            if query not in range(query_count):
                raise ValueError("output contains an out-of-range query index")
            if rank not in range(config.top_k):
                raise ValueError("output contains an out-of-range result rank")
            key = (query, rank, field)
            if expected_server in shares.setdefault(key, {}):
                raise ValueError("duplicate output share")
            shares[key][expected_server] = value % config.field_prime

    expected = {
        (query, rank, field)
        for query in range(query_count)
        for rank in range(config.top_k)
        for field in range(4)
    }
    if set(shares) != expected or any(
        set(server_shares) != set(range(SERVER_COUNT))
        for server_shares in shares.values()
    ):
        raise ValueError("missing or unexpected output shares")

    results: list[list[dict[str, int]]] = []
    for query in range(query_count):
        query_results = []
        for rank in range(config.top_k):
            row = {
                FIELD_NAMES[field]: reconstruct(
                    (
                        shares[(query, rank, field)][server]
                        for server in range(SERVER_COUNT)
                    ),
                    modulus=config.field_prime,
                )
                for field in range(4)
            }
            if row["valid"] not in (0, 1):
                raise ValueError("MPC returned a non-boolean validity value")
            if not row["valid"] and any(row[name] for name in FIELD_NAMES[1:]):
                raise ValueError("invalid MPC result has non-zero payload")
            query_results.append(row)
        results.append(query_results)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Reconstruct a packed private-lookup query batch at the client"
    )
    parser.add_argument("--config", required=True)
    parser.add_argument("--query-count", required=True, type=int)
    parser.add_argument("--server-log", action="append", required=True)
    parser.add_argument(
        "--relation-paged",
        action="store_true",
        help=(
            "read an EXPERIMENTAL relation-paged config; the client-side output "
            "contract is identical, only the config envelope differs"
        ),
    )
    args = parser.parse_args()
    if args.relation_paged:
        from .relation_pages import RelationPageConfig

        config = RelationPageConfig.load(args.config).base
    else:
        config = PublicConfig.load(args.config)
    results = decode_batch_logs(config, args.query_count, args.server_log)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
