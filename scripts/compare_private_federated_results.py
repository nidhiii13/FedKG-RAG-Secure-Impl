#!/usr/bin/env python3
"""Compare secure private JSONL output against a saved federated JSONL run."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def _read_jsonl(path: Path) -> list[dict]:
    rows = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def _avg(values: list[float]) -> float | None:
    return sum(values) / len(values) if values else None


def _round(value: float | None) -> float | None:
    return round(value, 4) if value is not None else None


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare secure private run with federated baseline")
    parser.add_argument("--private", required=True, help="Secure/private JSONL result file")
    parser.add_argument("--federated", required=True, help="Federated baseline JSONL result file")
    parser.add_argument("--details", action="store_true", help="Print one compact line per completed query")
    args = parser.parse_args()

    private_rows = _read_jsonl(Path(args.private))
    federated_rows = {
        index: row
        for index, row in enumerate(_read_jsonl(Path(args.federated)))
    }
    matched = [
        (row, federated_rows.get(row.get("index")))
        for row in private_rows
        if row.get("index") in federated_rows
    ]

    secure_retrieval = [row.get("retrieval_time", 0.0) for row, _ in matched if row.get("retrieval_time") is not None]
    federated_retrieval = [
        fed.get("retrieval_time", 0.0)
        for _, fed in matched
        if fed and fed.get("retrieval_time") is not None
    ]
    secure_answer = [row.get("answer_time", 0.0) for row, _ in matched if row.get("answer_time") is not None]

    summary = {
        "private_file": args.private,
        "federated_file": args.federated,
        "completed_private_rows": len(private_rows),
        "matched_rows": len(matched),
        "private_errors": sum(1 for row in private_rows if row.get("error_message")),
        "private_evidence_hits": sum(1 for row, _ in matched if row.get("evidence_contains_groundtruth")),
        "private_answer_correct": sum(1 for row, _ in matched if row.get("correct")),
        "federated_answer_correct_same_indices": sum(1 for _, fed in matched if fed and fed.get("correct")),
        "avg_private_retrieval_time": _round(_avg(secure_retrieval)),
        "avg_federated_retrieval_time_same_indices": _round(_avg(federated_retrieval)),
        "avg_private_answer_time": _round(_avg(secure_answer)),
    }
    print(json.dumps(summary, indent=2))

    if args.details:
        print("\nper_query")
        for row, fed in matched:
            print(
                "index={index} private_hit={hit} private_correct={pc} "
                "federated_correct={fc} private_rt={prt:.2f}s federated_rt={frt:.2f}s "
                "query={query}".format(
                    index=row.get("index"),
                    hit=row.get("evidence_contains_groundtruth"),
                    pc=row.get("correct"),
                    fc=fed.get("correct") if fed else None,
                    prt=row.get("retrieval_time") or 0.0,
                    frt=(fed or {}).get("retrieval_time") or 0.0,
                    query=str(row.get("query") or "")[:100],
                )
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
