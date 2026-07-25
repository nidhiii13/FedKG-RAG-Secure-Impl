#!/usr/bin/env python3
"""Run fixed-table bucketized N-party MP-SPDZ KG retrieval."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

from bucketed_oram_limb_index import ID_EFFECTIVE_BITS, ID_LIMBS, hmac_limbs
from decode_mpspdz_oram_output import _load_vaults, _resolve
from prepare_metaqa_mpspdz_inputs import _normalize_relation
from prepare_metaqa_twohop_mpspdz_inputs import _is_unknown, _load_manifest, _repo_root, _write_input_file
from prepare_metaqa_twohop_oram_mpspdz_inputs import _direction_bit
from prepare_metaqa_twohop_split_edge_join_mpspdz_inputs import _is_type_relation
from run_twohop_e2e import _parse_mpspdz_metrics, _run

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.semantic.relation_buckets import relation_bucket_names


OUTPUT_RE = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$")
LOW_VALUE_TOKENS = {"a", "an", "and", "by", "for", "in", "is", "of", "the", "to"}


def _edge_tuple(value: object) -> tuple[str, str, str]:
    if not isinstance(value, (list, tuple)) or len(value) != 3:
        raise ValueError("query graph edges must be [source, relation, target]")
    return str(value[0]), str(value[1]), str(value[2])


def _opposite_direction(direction_bit: int) -> int:
    return 1 - direction_bit


def _query_buckets(label: str, *, mode: str, limit: int) -> list[str]:
    buckets = relation_bucket_names(label, mode=mode)  # type: ignore[arg-type]
    ordered = []
    ordered.extend(sorted(bucket for bucket in buckets if bucket.startswith("alias:")))
    ordered.extend(
        sorted(
            bucket
            for bucket in buckets
            if bucket.startswith("tok:") and bucket.split(":", 1)[1] not in LOW_VALUE_TOKENS
        )
    )
    ordered.extend(
        sorted(
            bucket
            for bucket in buckets
            if bucket.startswith("bigram:")
            and not any(part in LOW_VALUE_TOKENS for part in bucket.split(":")[1:])
        )
    )
    ordered.extend(sorted(bucket for bucket in buckets if bucket.startswith("lsh:")))
    ordered.extend(sorted(bucket for bucket in buckets if bucket not in ordered))
    selected = list(dict.fromkeys(ordered))[:limit]
    if not selected:
        raise ValueError(f"relation label produced no semantic buckets: {label}")
    return selected


def _normalize_query(row: dict, setup_key: str, *, bucket_mode: str, max_query_buckets: int) -> tuple[dict, list[int]]:
    original_edges = [_edge_tuple(edge) for edge in (row.get("query_graph") or row.get("edges") or [])]
    if len(original_edges) == 1:
        original_edges.append((original_edges[0][2], "is a", "UNKNOWN"))
        synthetic_onehop = True
    elif len(original_edges) == 2:
        synthetic_onehop = False
    else:
        raise ValueError(f"bucketized MPC supports one or two edges, got {len(original_edges)}")

    first, second = original_edges
    _, direction_1 = _normalize_relation(first[1], semantic_relations=True)
    direction_1_bit = _direction_bit(direction_1)
    type_mode = bool(_is_type_relation(second[1]))
    if type_mode:
        relation_2_buckets: list[str] = []
        direction_2_bit = 0
    else:
        _, direction_2 = _normalize_relation(second[1], semantic_relations=True)
        direction_2_bit = _direction_bit(direction_2)
        relation_2_buckets = _query_buckets(second[1], mode=bucket_mode, limit=max_query_buckets)
    relation_1_buckets = _query_buckets(first[1], mode=bucket_mode, limit=max_query_buckets)

    zero = tuple(0 for _ in range(ID_LIMBS))
    relation_1_bucket_ids = [hmac_limbs(setup_key, "relation_bucket", bucket) for bucket in relation_1_buckets]
    relation_2_bucket_ids = [hmac_limbs(setup_key, "relation_bucket", bucket) for bucket in relation_2_buckets]
    relation_1_bucket_ids.extend([zero] * (max_query_buckets - len(relation_1_bucket_ids)))
    relation_2_bucket_ids.extend([zero] * (max_query_buckets - len(relation_2_bucket_ids)))

    target_is_unknown = _is_unknown(second[2])
    if target_is_unknown and not type_mode:
        raise ValueError("unknown-to-unknown second hop requires iterative frontier handling")
    target_id = zero if target_is_unknown else hmac_limbs(setup_key, "entity", second[2])
    normalized = {
        "index": row.get("index"),
        "query": row.get("query") or row.get("question"),
        "groundtruths": row.get("groundtruths") or row.get("answers") or [],
        "original_edges": [list(edge) for edge in (original_edges[:1] if synthetic_onehop else original_edges)],
        "type_identity_mode": type_mode,
        "synthetic_onehop": synthetic_onehop,
        "bucketized_mpc_routing": {
            "mode": bucket_mode,
            "edge_1_query_buckets": relation_1_buckets,
            "edge_2_query_buckets": [] if type_mode else relation_2_buckets,
            "max_query_buckets": max_query_buckets,
        },
    }
    values = [
        *hmac_limbs(setup_key, "entity", first[0]),
        *(limb for bucket_id in relation_1_bucket_ids for limb in bucket_id),
        direction_1_bit,
        *(limb for bucket_id in relation_2_bucket_ids for limb in bucket_id),
        _opposite_direction(direction_2_bit),
        *target_id,
        int(target_is_unknown),
        int(type_mode),
    ]
    return normalized, values


def _parse_outputs(output: str, query_count: int) -> list[list[tuple[int, int]]]:
    selected: list[list[tuple[int, int]]] = [[] for _ in range(query_count)]
    seen: list[set[tuple[int, int]]] = [set() for _ in range(query_count)]
    in_table = False
    for line in output.splitlines():
        if line.strip() == "query rank left_evidence_handle right_evidence_handle":
            in_table = True
            continue
        if not in_table:
            continue
        match = OUTPUT_RE.match(line)
        if not match:
            if any(selected):
                break
            continue
        query = int(match.group(1))
        left = int(match.group(3))
        right = int(match.group(4))
        if query >= query_count:
            raise ValueError(f"MP-SPDZ returned invalid query index {query}")
        pair = (left, right)
        if left and pair not in seen[query]:
            seen[query].add(pair)
            selected[query].append((left, right))
    return selected


def _contains_groundtruth(edges: list[list[str]], groundtruths: list[str]) -> bool:
    haystack = "\n".join(part for edge in edges for part in edge).lower()
    return bool(groundtruths) and any(str(answer).lower() in haystack for answer in groundtruths)


def _logical_right_edge(reverse_edge: dict | None) -> list[str] | None:
    if reverse_edge is None:
        return None
    return [reverse_edge["target"], reverse_edge["relation"], reverse_edge["source"]]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--index-dir", required=True)
    parser.add_argument("--queries-jsonl", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--instance-dir", required=True)
    parser.add_argument("--start-index", type=int, default=0)
    parser.add_argument("--max-queries", type=int, default=1)
    parser.add_argument("--max-query-buckets", type=int, default=4)
    parser.add_argument("--left-candidate-cap", type=int, default=32)
    parser.add_argument("--right-candidate-cap", type=int, default=32)
    parser.add_argument("--topk", type=int, default=3)
    parser.add_argument("--semantic-bucket-mode", choices=["alias", "lsh", "hybrid"], default="hybrid")
    parser.add_argument("--mp-spdz-home", default="external/MP-SPDZ")
    parser.add_argument("--skip-compile-if-present", action="store_true")
    args = parser.parse_args()

    setup_key = os.environ.get("FEDKG_SETUP_KEY")
    if not setup_key:
        raise SystemExit("FEDKG_SETUP_KEY is required")
    index_root = Path(args.index_dir)
    metadata = json.loads((index_root / "metadata.json").read_text())
    if metadata.get("format") != "fedkg-mpspdz-bucketized-index-set-v1":
        raise SystemExit("unsupported bucketized index-set format")
    if metadata.get("semantic_bucket_mode") != args.semantic_bucket_mode:
        raise SystemExit("semantic bucket mode mismatch")
    if args.max_query_buckets < 1:
        raise SystemExit("--max-query-buckets must be positive")
    if args.left_candidate_cap < args.topk:
        raise SystemExit("--left-candidate-cap must be at least --topk")
    if args.right_candidate_cap < args.topk:
        raise SystemExit("--right-candidate-cap must be at least --topk")
    rows_per_party = int(metadata["rows_per_party"])

    rows = []
    with Path(args.queries_jsonl).open() as handle:
        for line_number, line in enumerate(handle):
            if line_number < args.start_index:
                continue
            if len(rows) >= args.max_queries:
                break
            rows.append(json.loads(line))
    if not rows:
        raise SystemExit("no queries selected")

    normalized_queries = []
    query_values = []
    for row in rows:
        normalized, values = _normalize_query(
            row,
            setup_key,
            bucket_mode=args.semantic_bucket_mode,
            max_query_buckets=args.max_query_buckets,
        )
        normalized_queries.append(normalized)
        query_values.extend(values)

    manifest = _load_manifest(Path(args.manifest))
    party_ids = [party["party_id"] for party in manifest["parties"]]
    party_tables = [
        json.loads((index_root / party_id / "bucketized_mpc_table.json").read_text())["rows"]
        for party_id in party_ids
    ]

    instance_dir = Path(args.instance_dir)
    instance_dir.mkdir(parents=True, exist_ok=True)
    template = (
        _repo_root()
        / "mpspdz_client_excluded"
        / "programs"
        / "secure_kg_bucketized_twohop_topk.mpc.template"
    ).read_text()
    profile = {
        "data_parties": len(party_ids),
        "num_queries": len(rows),
        "rows_per_party": rows_per_party,
        "max_query_buckets": args.max_query_buckets,
        "left_candidate_cap": args.left_candidate_cap,
        "right_candidate_cap": args.right_candidate_cap,
        "top_k": args.topk,
    }
    profile_hash = hashlib.sha256(json.dumps(profile, sort_keys=True).encode()).hexdigest()[:16]
    program_name = f"secure_kg_bucketized_twohop_topk_{profile_hash}"
    (instance_dir / f"{program_name}.mpc").write_text(template.format(**profile))

    player_data = instance_dir / "Player-Data"
    query_path = player_data / "Input-P0-0"
    _write_input_file(query_path, query_values)
    query_path.chmod(0o600)
    for player, table in enumerate(party_tables, start=1):
        if len(table) != rows_per_party:
            raise SystemExit(f"party table has {len(table)} rows, expected {rows_per_party}")
        values = [value for row in table for value in row]
        input_path = player_data / f"Input-P{player}-0"
        _write_input_file(input_path, values)
        input_path.chmod(0o600)

    receipt = {
        "format": "fedkg-mpspdz-bucketized-batch-v1",
        "id_limbs": ID_LIMBS,
        "id_effective_bits": ID_EFFECTIVE_BITS,
        "index_dir": str(index_root.resolve()),
        "data_parties": [{"party_id": party_id} for party_id in party_ids],
        "queries": normalized_queries,
        "rows_per_party": rows_per_party,
        "left_candidate_cap": args.left_candidate_cap,
        "right_candidate_cap": args.right_candidate_cap,
        "mp_spdz_program": program_name,
        "circuit_profile_hash": profile_hash,
        "security_note": (
            "Fixed padded bucketized MPC scan with fixed candidate caps; table size "
            "and caps are public and query independent."
        ),
    }
    (instance_dir / "query_gateway_receipt.json").write_text(json.dumps(receipt, indent=2))

    print(f"Prepared {len(rows)} bucketized MPC queries.", flush=True)
    started = time.perf_counter()
    run_env = os.environ.copy()
    run_env["MP_SPDZ_HOME"] = args.mp_spdz_home
    bytecode_dir = Path(args.mp_spdz_home) / "Programs" / "Bytecode"
    compile_skipped = False
    if args.skip_compile_if_present and any(bytecode_dir.glob(f"{program_name}*.bc")):
        run_env["MP_SPDZ_SKIP_COMPILE"] = "1"
        compile_skipped = True
    mpc = _run(
        ["bash", str(REPO_ROOT / "mpspdz_client_excluded" / "scripts" / "run_mpspdz_oram_instance.sh"), str(instance_dir)],
        env=run_env,
        cwd=REPO_ROOT,
    )
    elapsed = time.perf_counter() - started
    (instance_dir / "mp_spdz_output.txt").write_text(mpc.stdout)
    selected = _parse_outputs(mpc.stdout, len(rows))
    vaults = _load_vaults(receipt)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    correct = 0
    records = []
    for query_number, (query, handles) in enumerate(zip(normalized_queries, selected)):
        paths = []
        all_edges = []
        for rank, (left_handle, right_handle) in enumerate(handles):
            left = _resolve(left_handle, vaults)
            right = _resolve(right_handle, vaults)
            edges = [[left["source"], left["relation"], left["target"]]]
            logical_right = _logical_right_edge(right)
            if logical_right is not None:
                edges.append(logical_right)
            paths.append({"rank": rank, "edges": edges})
            all_edges.extend(edges)
        is_correct = _contains_groundtruth(all_edges, query["groundtruths"])
        correct += int(is_correct)
        record = {
            **query,
            "status": "ok",
            "bucketized_mpc_correct": is_correct,
            "selected_paths": paths,
        }
        records.append(record)
        print(
            f"[{query_number + 1}/{len(rows)}] index={query['index']} "
            f"correct={is_correct} paths={len(paths)} query={query['query']}",
            flush=True,
        )
    with output_path.open("w") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    print(
        json.dumps(
            {
                "total": len(rows),
                "correct": correct,
                "accuracy": correct / len(rows),
                "batch_e2e_seconds": elapsed,
                "average_amortized_seconds": elapsed / len(rows),
                "mp_spdz_metrics": _parse_mpspdz_metrics(mpc.stdout),
                "output": str(output_path),
                "instance_dir": str(instance_dir),
                "rows_per_party": rows_per_party,
                "max_query_buckets": args.max_query_buckets,
                "left_candidate_cap": args.left_candidate_cap,
                "right_candidate_cap": args.right_candidate_cap,
                "compile_skipped": compile_skipped,
                "mp_spdz_program": program_name,
                "circuit_profile_hash": profile_hash,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
