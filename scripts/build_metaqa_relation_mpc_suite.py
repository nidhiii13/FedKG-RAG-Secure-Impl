#!/usr/bin/env python3
"""Split the fixed MetaQA q500 sample into two privacy-preserving MPC buckets.

The public bucket distinguishes person/movie traversal from attribute lookup.
It does not reveal the source entity or exact relation pair.  Each bucket uses
six relations instead of the full eighteen-relation ontology, which materially
reduces the generated circuit and its compilation memory requirement.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

ATTRIBUTE_RELATIONS = {
    "release_year",
    "in_language",
    "has_genre",
    "has_tags",
    "has_imdb_rating",
    "has_imdb_votes",
}


def read_json(path: Path, expected: type) -> Any:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, expected):
        raise ValueError(f"{path} must contain a {expected.__name__}")
    return value


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def bucket_for(query: dict[str, str]) -> str:
    return "attribute_lookup" if query["relation_2"] in ATTRIBUTE_RELATIONS else "person_movie"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source-fixture",
        type=Path,
        default=Path("data/metaqa/relation_fixture/full_domain_q500_b8"),
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("data/metaqa/relation_fixture/q500_private_bucket_suite_b8"),
    )
    parser.add_argument("--bound", type=int, default=8)
    parser.add_argument("--top-k", type=int, default=4)
    parser.add_argument("--seed", type=int, default=4242)
    args = parser.parse_args()

    queries = read_json(args.source_fixture / "queries.json", list)
    expected = read_json(args.source_fixture / "expected_answers.json", list)
    if len(queries) != len(expected):
        raise ValueError("source fixture queries and expected answers are not aligned")

    grouped: dict[str, list[tuple[dict[str, str], dict[str, Any]]]] = defaultdict(list)
    for query, answer in zip(queries, expected, strict=True):
        grouped[bucket_for(query)].append((query, answer))
    if set(grouped) != {"attribute_lookup", "person_movie"}:
        raise ValueError(f"unexpected MetaQA bucket set: {sorted(grouped)}")

    manifests = []
    for bucket in sorted(grouped):
        rows = grouped[bucket]
        indices = [int(answer["index"]) for _, answer in rows]
        relations = sorted({
            relation
            for query, _ in rows
            for relation in (query["relation_1"], query["relation_2"])
        })
        bucket_dir = args.out / "fixtures" / bucket
        indices_path = args.out / "question_indices" / f"{bucket}.json"
        relations_path = args.out / "relation_allowlists" / f"{bucket}.json"
        write_json(indices_path, indices)
        write_json(relations_path, relations)
        command = [
            sys.executable,
            str(ROOT / "scripts/build_metaqa_relation_mpc_fixture.py"),
            "--out", str(bucket_dir),
            "--questions", "0",
            "--bound", str(args.bound),
            "--top-k", str(args.top_k),
            "--seed", str(args.seed),
            "--question-indices", str(indices_path),
            "--relation-allowlist", str(relations_path),
            "--public-scope-label", bucket,
            "--base-fixture", str(args.source_fixture),
        ]
        print(f"building {bucket}: {len(rows)} questions, {len(relations)} relations", flush=True)
        subprocess.run(command, check=True)
        capacity_path = bucket_dir / "capacity_report.json"
        validation_path = bucket_dir / "cleartext_validation.json"
        capacity = read_json(capacity_path, dict)
        validation = read_json(validation_path, dict)
        manifests.append({
            "bucket": bucket,
            "questions": len(rows),
            "relations": relations,
            "entities": capacity["entities"],
            "directed_edges_after_bound": capacity["directed_edges_after_bound"],
            "directory_rows": capacity["actual_directory_rows"],
            "evidence_hits": validation["evidence_hits"],
            "fixture": str(bucket_dir),
            "capacity_sha256": sha256(capacity_path),
            "cleartext_validation_sha256": sha256(validation_path),
        })

    manifest = {
        "evaluation_label": "MetaQA q500 two-bucket native-MPC suite",
        "source_fixture": str(args.source_fixture),
        "selected_questions": len(queries),
        "public_buckets": 2,
        "public_leakage": (
            "a coarse person/movie-versus-attribute workload class and circuit dimensions; "
            "the source entity and exact relation pair remain secret-shared"
        ),
        "parameters": {"owners": 3, "bound": args.bound, "top_k": args.top_k, "seed": args.seed},
        "buckets": manifests,
    }
    write_json(args.out / "manifest.json", manifest)
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
