#!/usr/bin/env python3
"""Run Lattigo N-party threshold PIR over encoded KG bucket records."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.crypto.hmac_ids import HmacIdProvider
from src.aggregation.prio3_backend import Prio3BackendError, Prio3LocalBackend
from src.aggregation.prio3_candidates import (
    CandidateContribution,
    CandidateVectorConfig,
    PrioCandidateAggregator,
    SessionCandidateHandleProvider,
)
from src.aggregation.score_aggregation import CandidateShare, candidate_id_for_edges
from src.aggregation.secret_sharing import AdditiveSharing, FixedPointEncoder
from src.ranking.garbled_circuit import LocalGarbledCircuitTopK
from src.semantic.relation_buckets import relation_bucket_tokens

UNKNOWN_PREFIX = "UNKNOWN"
TYPE_RELATIONS = {
    "is a",
    "is an",
    "is one of",
    "isa",
    "type",
    "types",
    "genre",
}
ACTOR_RELATION_ALIASES = {
    "acted in",
    "actor of",
    "appear in",
    "appeared in",
    "appears in",
    "star of",
    "starred in",
    "is starred by",
    "appeared by",
    "have actor",
    "has actor",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Lattigo threshold-PIR bucket retrieval plus bounded join.")
    parser.add_argument("--index-dir", required=True, type=Path)
    parser.add_argument("--edge", action="append", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--key-env", default="FEDKG_SETUP_KEY")
    parser.add_argument("--semantic-bucket-mode", choices=("alias", "lsh", "hybrid"), default="alias")
    parser.add_argument("--max-query-buckets", type=int, default=1)
    parser.add_argument("--topk", type=int, default=3)
    parser.add_argument("--parties", type=int, default=3)
    parser.add_argument("--threshold", type=int, default=2)
    parser.add_argument("--prio-aggregators", type=int, default=3)
    parser.add_argument("--candidate-capacity", type=int, default=256)
    parser.add_argument("--handle-key-env", default="FEDKG_PRIO_HANDLE_KEY")
    parser.add_argument("--query-nonce", default="lattigo-threshold-pir-validation")
    parser.add_argument("--prio-cli", type=Path, default=Path("tools/prio3_cli/target/release/fedkg-prio3-cli"))
    parser.add_argument("--go-routines", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument(
        "--lattigo-pir",
        type=Path,
        default=Path("tools/lattigo_threshold_pir/lattigo-fedkg-threshold-pir"),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    total_start = time.perf_counter()
    ids = HmacIdProvider.from_env(args.key_env)
    original_edges = _parse_edges(args.edge)
    edges, simplification = simplify_query_edges(original_edges)

    load_start = time.perf_counter()
    metadata = json.loads((args.index_dir / "metadata.json").read_text())
    directory = json.loads((args.index_dir / "directory.json").read_text())
    id_map = _load_id_map(args.index_dir)
    record_size = int(metadata["record_size"])
    load_seconds = time.perf_counter() - load_start

    retrieve_start = time.perf_counter()
    requests = _edge_requests(edges, ids, args, directory)
    records_by_index = _run_lattigo_batch(
        args,
        args.index_dir / "records.jsonl",
        sorted({request["index"] for request in requests}),
        record_size,
    )
    retrieved = [
        _records_for_edge(requests, records_by_index, edge_index, id_map)
        for edge_index in range(len(edges))
    ]
    retrieve_seconds = time.perf_counter() - retrieve_start

    join_start = time.perf_counter()
    candidates = _join_paths(retrieved, args.topk)
    ranked = _aggregate_and_rank(candidates, args)
    join_seconds = time.perf_counter() - join_start

    payload = {
        "query": original_edges,
        "effective_query": edges,
        "query_simplification": simplification,
        "pir_backend": {
            "type": "lattigo-threshold-bgv-pir",
            "parties": args.parties,
            "threshold": args.threshold,
            "database_size": metadata["database_size"],
            "record_size": record_size,
            "semantic_bucket_mode": metadata.get("semantic_bucket_mode"),
            "relation_filter": metadata.get("relation_filter", []),
            "entity_filter": metadata.get("entity_filter", []),
            "security_model": "N-party threshold PIR; output decryption requires threshold parties",
        },
        "candidate_count": len(candidates),
        "selected_candidate_ids": ranked["selected_candidate_ids"],
        "selected_encoded_paths": [
            candidate for candidate in candidates if candidate["candidate_id"] in set(ranked["selected_candidate_ids"])
        ][: args.topk],
        "post_retrieval_validation": ranked["validation"],
        "timing_seconds": {
            "load_index_metadata": round(load_seconds, 6),
            "threshold_pir_retrieval": round(retrieve_seconds, 6),
            "bounded_join_prio_and_gc_validation": round(join_seconds, 6),
            "total": round(time.perf_counter() - total_start, 6),
        },
    }
    rendered = json.dumps(payload, indent=2, sort_keys=True)
    print(rendered)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n")
    return 0


def _edge_requests(
    edges: list[tuple[str, str, str]],
    ids: HmacIdProvider,
    args: argparse.Namespace,
    directory: dict[str, int],
) -> list[dict[str, int]]:
    requests: list[dict[str, int]] = []
    for edge_index, edge in enumerate(edges):
        source, relation, target = edge
        buckets = relation_bucket_tokens(ids, relation, mode=args.semantic_bucket_mode)
        if args.max_query_buckets > 0:
            buckets = buckets[: args.max_query_buckets]
        if not _is_unknown(source):
            direction = "forward"
            entity_id = ids.entity_id(source)
        elif not _is_unknown(target):
            direction = "reverse"
            entity_id = ids.entity_id(target)
        else:
            raise ValueError("each threshold-PIR edge must bind either source or target")
        for bucket in buckets:
            directory_entry = directory.get(f"{direction}:{entity_id}:{bucket}")
            if directory_entry is not None:
                requests.append(
                    {
                        "edge_index": edge_index,
                        "index": _directory_row_index(directory_entry),
                        "offset": _directory_offset(directory_entry),
                        "key": f"{direction}:{entity_id}:{bucket}",
                    }
                )
    return requests


def _run_lattigo_batch(
    args: argparse.Namespace,
    records_path: Path,
    indices: list[int],
    record_size: int,
) -> dict[int, dict]:
    if not indices:
        return {}
    command = [
        str(args.lattigo_pir),
        "--records-jsonl",
        str(records_path),
        "--indices",
        ",".join(str(index) for index in indices),
        "--record-size",
        str(record_size),
        "--parties",
        str(args.parties),
        "--threshold",
        str(args.threshold),
        "--go-routines",
        str(args.go_routines),
    ]
    completed = subprocess.run(
        command,
        text=True,
        capture_output=True,
        timeout=args.timeout,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit(completed.stderr.strip() or "Lattigo threshold PIR failed")
    lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    if not lines:
        raise SystemExit("Lattigo threshold PIR produced no output")
    payload = json.loads(lines[-1])
    return {
        int(record["query_index"]): record["record_json"]
        for record in payload.get("records", [])
    }


def _records_for_edge(
    requests: list[dict[str, int]],
    records_by_index: dict[object, dict],
    edge_index: int,
    id_map: dict[str, str] | None = None,
) -> list[tuple[str, str, str]]:
    out: set[tuple[str, str, str]] = set()
    for request in requests:
        if request["edge_index"] != edge_index:
            continue
        record = records_by_index.get(request["index"])
        if not record:
            continue
        logical_record = _logical_record_for_request(record, request)
        if not logical_record:
            continue
        for encoded_edge in logical_record["edges"]:
            out.add(_decode_edge_ids(encoded_edge, id_map))
    return sorted(out)


def _directory_row_index(entry: object) -> int:
    if isinstance(entry, int):
        return entry
    if isinstance(entry, dict):
        return int(entry["row"])
    raise TypeError(f"unsupported directory entry: {entry!r}")


def _directory_offset(entry: object) -> int | None:
    if isinstance(entry, int):
        return None
    if isinstance(entry, dict):
        return int(entry.get("offset", 0))
    raise TypeError(f"unsupported directory entry: {entry!r}")


def _logical_record_for_request(record: dict, request: dict) -> dict | None:
    if "edges" in record:
        return record
    packed = record.get("records")
    if not isinstance(packed, list):
        return None
    offset = request.get("offset")
    if offset is None:
        for candidate in packed:
            if candidate.get("key") == request.get("key"):
                return candidate
        return None
    if offset < 0 or offset >= len(packed):
        return None
    candidate = packed[offset]
    if "key" in candidate and candidate.get("key") != request.get("key"):
        return None
    return candidate


def _load_id_map(index_dir: Path) -> dict[str, str] | None:
    path = index_dir / "id_map.json"
    if not path.exists():
        return None
    payload = json.loads(path.read_text())
    return {str(key): str(value) for key, value in payload.get("int_to_hmac", {}).items()}


def _decode_edge_ids(edge: list[object], id_map: dict[str, str] | None) -> tuple[str, str, str]:
    if id_map is None:
        return tuple(str(value) for value in edge)  # type: ignore[return-value]
    if len(edge) != 3:
        raise ValueError(f"invalid compact edge: {edge!r}")
    return tuple(id_map[str(value)] for value in edge)  # type: ignore[return-value]


def _join_paths(retrieved: list[list[tuple[str, str, str]]], topk: int) -> list[dict[str, object]]:
    if len(retrieved) == 1:
        return [_candidate_payload([edge]) for edge in retrieved[0][:topk]]
    candidates = []
    for left in retrieved[0]:
        for right in retrieved[1]:
            if left[2] == right[0]:
                candidates.append(_candidate_payload([left, right]))
    candidates.sort(key=lambda item: json.dumps(item["edges"], sort_keys=True))
    return candidates


def _candidate_payload(edges: list[tuple[str, str, str]]) -> dict[str, object]:
    return {
        "candidate_id": candidate_id_for_edges(edges),
        "score": 1.0,
        "support": len(edges),
        "edges": [list(edge) for edge in edges],
    }


def simplify_query_edges(edges: list[tuple[str, str, str]]) -> tuple[list[tuple[str, str, str]], dict[str, object]]:
    """Apply public, deterministic query-plan simplifications before PIR."""
    if len(edges) != 2:
        return edges, {"applied": False, "rule": None}

    first, second = edges
    if _is_redundant_type_constraint(first, second):
        return [first], {
            "applied": True,
            "rule": "drop_type_constraint",
            "removed_edges": [second],
        }
    if _is_reverse_duplicate(first, second):
        return [first], {
            "applied": True,
            "rule": "drop_reverse_duplicate",
            "removed_edges": [second],
        }
    return edges, {"applied": False, "rule": None}


def _is_redundant_type_constraint(
    first: tuple[str, str, str],
    second: tuple[str, str, str],
) -> bool:
    _, _, first_target = first
    second_source, second_relation, second_target = second
    if _relation_text(second_relation) not in TYPE_RELATIONS:
        return False
    if not (_is_unknown(first_target) and second_source == first_target):
        return False
    return _is_unknown(second_target)


def _is_reverse_duplicate(
    first: tuple[str, str, str],
    second: tuple[str, str, str],
) -> bool:
    first_source, first_relation, first_target = first
    second_source, second_relation, second_target = second
    return (
        _is_unknown(first_target)
        and second_source == first_target
        and second_target == first_source
        and _relation_text(first_relation) in ACTOR_RELATION_ALIASES
        and _relation_text(second_relation) in ACTOR_RELATION_ALIASES
    )


def _relation_text(value: str) -> str:
    return " ".join(str(value).replace("_", " ").lower().split())


def _aggregate_and_rank(candidates: list[dict[str, object]], args: argparse.Namespace) -> dict[str, object]:
    if len(candidates) > args.candidate_capacity:
        raise SystemExit(
            f"candidate count {len(candidates)} exceeds --candidate-capacity {args.candidate_capacity}"
        )
    sharing = AdditiveSharing()
    encoder = FixedPointEncoder()
    candidate_shares = [
        CandidateShare(
            candidate_id=str(candidate["candidate_id"]),
            score_shares=sharing.share(encoder.encode(float(candidate["score"])), args.parties),
            support_shares=sharing.share(int(candidate["support"]), args.parties),
        )
        for candidate in candidates
    ]
    selected_ids = list(LocalGarbledCircuitTopK(party_count=args.parties).rank(candidate_shares, args.topk))
    validation: dict[str, object] = {
        "score_support_shares": "additive shares over threshold PIR parties",
        "ranking": "local GC-compatible validation over additive shares",
        "production_requirement": "replace local validation with distributed MPC/GC top-k over aggregate shares",
    }

    handle_key = os.environ.get(args.handle_key_env)
    if handle_key and args.prio_cli.exists() and candidates:
        contributions = [
            CandidateContribution(
                party_id="threshold_pir_result",
                candidate_id=str(candidate["candidate_id"]),
                score=float(candidate["score"]),
                support=int(candidate["support"]),
            )
            for candidate in candidates
        ]
        try:
            aggregation = PrioCandidateAggregator(
                Prio3LocalBackend.from_executable(args.prio_cli),
                CandidateVectorConfig(
                    aggregator_count=args.prio_aggregators,
                    capacity=args.candidate_capacity,
                ),
                SessionCandidateHandleProvider(
                    handle_key.encode("utf-8"),
                    args.query_nonce.encode("utf-8"),
                ),
            ).aggregate(["threshold_pir_result"], contributions)
            validation["prio"] = {
                "aggregator_count": aggregation.aggregator_count,
                "party_count": aggregation.party_count,
                "aggregate_candidate_count": len(aggregation.candidates),
                "mode": "local Prio3 validation over bounded candidate vectors",
            }
        except Prio3BackendError as exc:
            validation["prio_error"] = str(exc)
    else:
        validation["prio"] = "skipped; set FEDKG_PRIO_HANDLE_KEY and provide --prio-cli to validate Prio aggregation"

    return {
        "selected_candidate_ids": selected_ids,
        "validation": validation,
    }


def _parse_edges(values: list[str]) -> list[tuple[str, str, str]]:
    edges = []
    for value in values:
        parts = tuple(part.strip() for part in value.split("|"))
        if len(parts) != 3 or any(not part for part in parts):
            raise SystemExit(f"invalid --edge value: {value!r}")
        edges.append(parts)
    if len(edges) not in (1, 2):
        raise SystemExit("this threshold-PIR runner supports one-hop or two-hop path queries")
    return edges  # type: ignore[return-value]


def _is_unknown(value: str) -> bool:
    return value.strip().upper().startswith(UNKNOWN_PREFIX)


if __name__ == "__main__":
    raise SystemExit(main())
