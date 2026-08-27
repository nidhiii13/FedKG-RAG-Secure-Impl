#!/usr/bin/env python3
"""Export the validated KQA Pro two-hop fixture for the generic RAG answer runner.

This does not rerun MPC.  It converts the cleartext-oracle records (whose packed
outputs were already compared with MP-SPDZ) into the ``per_question.jsonl``
schema consumed by ``scripts/run_rag_answers.py``.  Evidence handles are resolved
against the three owner files and every recovered path is checked against the
query and endpoint before it is emitted.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def wilson(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    if total == 0:
        return 0.0, 0.0
    p = successes / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    radius = z * ((p * (1 - p) / total + z * z / (4 * total * total)) ** 0.5) / denominator
    return max(0.0, centre - radius), min(1.0, centre + radius)


def load_names(kb_path: Path) -> dict[str, str]:
    kb = read_json(kb_path)
    names: dict[str, str] = {}
    for section in ("concepts", "entities"):
        for node_id, node in kb.get(section, {}).items():
            names[node_id] = str(node.get("name") or node_id)
    return names


def load_edges(fixture: Path) -> tuple[dict[int, dict[str, Any]], list[int]]:
    by_handle: dict[int, dict[str, Any]] = {}
    owner_sizes: list[int] = []
    for owner_path in sorted(fixture.glob("owner_*.json")):
        rows = read_json(owner_path)
        owner_sizes.append(len(rows))
        for edge in rows:
            handle = int(edge["evidence"])
            if handle <= 0:
                raise ValueError(f"non-positive evidence handle {handle} in {owner_path}")
            if handle in by_handle:
                raise ValueError(f"duplicate evidence handle {handle}")
            by_handle[handle] = edge
    if not owner_sizes:
        raise ValueError(f"no owner_*.json files found under {fixture}")
    return by_handle, owner_sizes


def checked_path(
    output: dict[str, Any],
    query: dict[str, Any],
    endpoint_ids: set[str],
    edges: dict[int, dict[str, Any]],
    names: dict[str, str],
) -> dict[str, Any]:
    left_handle = int(output["left_evidence"])
    right_handle = int(output["right_evidence"])
    try:
        left = edges[left_handle]
        right = edges[right_handle]
    except KeyError as exc:
        raise ValueError(f"unresolved evidence handle {exc.args[0]}") from exc

    expected = (
        left["source"] == query["source"]
        and left["relation"] == query["relation_1"]
        and left["target"] == right["source"]
        and right["relation"] == query["relation_2"]
        and right["target"] in endpoint_ids
    )
    if not expected:
        raise ValueError(
            "evidence handles do not form the declared two-hop query path: "
            f"{left_handle}, {right_handle}"
        )

    return {
        "score": int(output["score"]),
        "edges": [
            [names.get(left["source"], left["source"]), left["relation"],
             names.get(left["target"], left["target"])],
            [names.get(right["source"], right["source"]), right["relation"],
             names.get(right["target"], right["target"])],
        ],
        "evidence_handles": [left_handle, right_handle],
        "endpoint_id": right["target"],
    }


def export_run(
    fixture: Path,
    kb_path: Path,
    out_dir: Path,
    mpc_summary_path: Path | None = None,
) -> dict[str, Any]:
    validation = read_json(fixture / "cleartext_validation.json")
    answers = {
        row["uid"]: row for row in read_json(fixture / "expected_answers.json")
    }
    names = load_names(kb_path)
    edges, owner_sizes = load_edges(fixture)

    mpc_summary = read_json(mpc_summary_path) if mpc_summary_path else None
    if mpc_summary is not None:
        if not mpc_summary.get("all_exact"):
            raise ValueError("the supplied MPC summary is not an all-exact run")
        if int(mpc_summary.get("queries", -1)) != int(validation["queries"]):
            raise ValueError("MPC summary query count does not match the fixture")

    records: list[dict[str, Any]] = []
    for result in validation["records"]:
        answer = answers.get(result["uid"])
        if answer is None:
            raise ValueError(f"missing expected answer for {result['uid']}")
        expected_ids = set(result["expected_endpoint_ids"])
        if expected_ids != set(answer["endpoint_ids"]):
            raise ValueError(f"endpoint mismatch for {result['uid']}")

        evidence = [
            checked_path(item, result["query"], expected_ids, edges, names)
            for item in result["oracle_output"]
            if int(item["valid"]) == 1
        ]
        actual_ids = set(result["actual_endpoint_ids"])
        hit = bool(actual_ids & expected_ids)
        records.append({
            "uid": result["uid"],
            "dataset": "kqa_pro",
            "evaluation_scope": validation["evaluation_label"],
            "query": answer["question"],
            "groundtruths": [answer["answer"]],
            "groundtruth_endpoint_ids": sorted(expected_ids),
            "retrieved_endpoint_ids": sorted(actual_ids),
            "hops": result["query"],
            "evidence": evidence,
            "hit": hit,
            "exact_endpoint_match": bool(result["exact"]),
            "mpc_output_verified": mpc_summary is not None,
        })

    hits = sum(bool(row["hit"]) for row in records)
    exact = sum(bool(row["exact_endpoint_match"]) for row in records)
    low, high = wilson(hits, len(records))
    summary: dict[str, Any] = {
        "dataset": "KQA Pro",
        "evaluation_label": validation["evaluation_label"],
        "full_kqapro_accuracy": False,
        "scope_note": (
            "Questions compatible with the fixed snapshot and two-hop relation-only "
            "functionality; not the complete KQA Pro task. A train+validation export "
            "is a systems/correctness benchmark, not a held-out accuracy estimate."
        ),
        "queries": len(records),
        "retrieval_hits": hits,
        "retrieval_hit_rate": hits / len(records) if records else None,
        "retrieval_hit_ci95": [low, high],
        "exact_endpoint_matches": exact,
        "exact_endpoint_match_rate": exact / len(records) if records else None,
        "owners": len(owner_sizes),
        "owner_edge_counts": owner_sizes,
        "fixture_edges": sum(owner_sizes),
        "mpc_verified": mpc_summary is not None,
        "mpc_summary": str(mpc_summary_path) if mpc_summary_path else None,
    }
    if mpc_summary is not None:
        summary["mpc"] = {
            "protocol": mpc_summary["protocol"],
            "measurement_scope": mpc_summary["measurement_scope"],
            "total_seconds_including_preprocessing": mpc_summary[
                "total_mpc_seconds_including_preprocessing"
            ],
            "seconds_per_query": mpc_summary["amortized_mpc_seconds_per_query"],
            "total_global_data_mb": mpc_summary["total_global_data_mb"],
            "global_mb_per_query": mpc_summary["amortized_global_mb_per_query"],
            "security_note": mpc_summary["security_note"],
        }

    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "per_question.jsonl").open("w", encoding="utf-8") as stream:
        for row in records:
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")
    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fixture", type=Path,
        default=Path("data/kqa_pro/relation_fixture/validation_closure"),
    )
    parser.add_argument("--kb", type=Path, default=Path("data/kqa_pro/raw/kb.json"))
    parser.add_argument("--mpc-summary", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    summary = export_run(args.fixture, args.kb, args.out, args.mpc_summary)
    print(
        f"KQA Pro retrieval: {summary['retrieval_hits']}/{summary['queries']} "
        f"({100 * summary['retrieval_hit_rate']:.2f}%)"
    )
    print(
        f"scope: {summary['evaluation_label']} "
        f"(full KQA Pro accuracy: {summary['full_kqapro_accuracy']})"
    )
    print(f"MPC output verified: {summary['mpc_verified']}")
    print(f"wrote {args.out / 'summary.json'} and per_question.jsonl")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
