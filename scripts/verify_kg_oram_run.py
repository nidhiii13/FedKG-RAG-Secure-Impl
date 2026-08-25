#!/usr/bin/env python3
"""Reconstruct a wide-record KG-ORAM run and check a raw-edge oracle."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from doram_t2_3pc.decode_batch import decode_batch_logs  # noqa: E402
from doram_t2_3pc.relation_pages import (  # noqa: E402
    RelationPageConfig,
    evaluate_paged_cleartext,
)


def _rows(path: Path) -> list[dict[str, object]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise ValueError(f"expected a JSON list of objects: {path}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--queries", required=True, type=Path)
    parser.add_argument("--owner-edges", action="append", required=True)
    parser.add_argument("--server-log", action="append", required=True, type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    config = RelationPageConfig.load(args.config)
    owner_paths: dict[str, Path] = {}
    for item in args.owner_edges:
        owner, separator, path = item.partition("=")
        if not separator or owner in owner_paths:
            raise ValueError("--owner-edges requires unique OWNER=PATH values")
        owner_paths[owner] = Path(path)
    if set(owner_paths) != set(config.base.owners):
        raise ValueError("owner edge files do not match the public federation")

    queries = _rows(args.queries)
    edges = {owner: _rows(owner_paths[owner]) for owner in config.base.owners}
    expected = [evaluate_paged_cleartext(config, edges, query) for query in queries]
    reconstructed = decode_batch_logs(config.base, len(queries), args.server_log)
    matches = [actual == wanted for actual, wanted in zip(reconstructed, expected)]
    report = {
        "backend": "wide-record-recursive-readonly-kg-oram",
        "query_count": len(queries),
        "distinct_query_count": len({json.dumps(row, sort_keys=True) for row in queries}),
        "fields_compared": len(queries) * config.base.top_k * 4,
        "matching_queries": sum(matches),
        "per_query_match": matches,
        "exact_match": all(matches),
        "expected": expected,
        "reconstructed": reconstructed,
    }
    rendered = json.dumps(report, indent=2) + "\n"
    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if report["exact_match"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
