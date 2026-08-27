#!/usr/bin/env python3
"""Build auditable KQA Pro fixtures for the relation-paged MPC backend.

Two artifacts are intentionally kept separate:

``full``
    Every unique directed entity relation in the frozen KQA Pro KB. This is the
    honest capacity/scalability fixture. It is expected to be too expensive for
    an immediate MPC run because public lossless degree bounds are large.

``validation_closure``
    Every first- and second-hop edge reachable from all compatible validation
    queries. Selection uses only public query anchors and relation pairs, never
    the published answers. This is a controlled correctness fixture, not a
    whole-KB scalability result.

Both use a deterministic synthetic three-owner split and the same public
ontology derived from the frozen benchmark KB. KQA Pro has no owner provenance.
The type map is suitable for this public benchmark only: a private deployment
must obtain it independently of owners' secret edges.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from doram_t2_3pc.compact_directory import bucket_of  # noqa: E402
from doram_t2_3pc.config import HE_SCALABLE_FIELD_PRIME  # noqa: E402
from doram_t2_3pc.relation_pages import (  # noqa: E402
    RelationPageConfig,
    build_owner_page_layout,
    check_global_frontier,
    evaluate_paged_cleartext,
    owner_layout_report,
    paged_cost_estimate,
)


OWNER_NAMES = ("owner_0", "owner_1", "owner_2")
UNTYPED = "\x00untyped"
CONCEPT_NODE = "\x00concept-node"


def load_json(path: Path, expected: type) -> Any:
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, expected):
        raise ValueError(f"{path} must contain a {expected.__name__}")
    return payload


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{number} is not an object")
            rows.append(row)
    return rows


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def relation_label(record: Mapping[str, Any]) -> str:
    predicate = record.get("predicate")
    direction = record.get("direction")
    if not isinstance(predicate, str) or direction not in {"forward", "backward"}:
        raise ValueError("invalid KQA relation record")
    return predicate if direction == "forward" else f"{predicate}_inverse"


def directed_triples(kb: Mapping[str, Any]) -> list[tuple[str, str, str]]:
    triples: set[tuple[str, str, str]] = set()
    entities = kb.get("entities")
    concepts = kb.get("concepts")
    if not isinstance(entities, dict) or not isinstance(concepts, dict):
        raise ValueError("KQA KB requires entities and concepts objects")
    known = set(entities) | set(concepts)
    for source, entity in entities.items():
        for record in entity.get("relations", []):
            target = record.get("object")
            if target not in known:
                raise ValueError(f"relation from {source} targets unknown node {target}")
            triples.add((source, relation_label(record), str(target)))
    return sorted(triples)


def public_primary_types(kb: Mapping[str, Any]) -> dict[str, str]:
    """Choose one deterministic primary type from the public frozen ontology."""
    entities: Mapping[str, Any] = kb["entities"]
    concepts: Mapping[str, Any] = kb["concepts"]
    frequencies: Counter[str] = Counter()
    for entity in entities.values():
        direct = entity.get("instanceOf", [])
        if isinstance(direct, list):
            frequencies.update(value for value in direct if isinstance(value, str))

    result: dict[str, str] = {}
    for entity_id, entity in entities.items():
        direct = [
            value
            for value in entity.get("instanceOf", [])
            if isinstance(value, str) and value in concepts
        ]
        result[entity_id] = (
            max(sorted(direct), key=lambda value: (frequencies[value], value))
            if direct
            else UNTYPED
        )
    for concept_id in concepts:
        result[concept_id] = CONCEPT_NODE
    return result


def contiguous_entity_ids(primary_types: Mapping[str, str]) -> dict[str, int]:
    ordered = sorted(primary_types, key=lambda node: (primary_types[node], node))
    return {node: index for index, node in enumerate(ordered, start=1)}


def relation_domains(
    triples: Iterable[tuple[str, str, str]], primary_types: Mapping[str, str]
) -> dict[str, str]:
    counts: dict[str, Counter[str]] = defaultdict(Counter)
    for source, relation, _ in triples:
        counts[relation][primary_types[source]] += 1
    return {
        relation: max(sorted(by_type), key=lambda value: (by_type[value], value))
        for relation, by_type in counts.items()
    }


def owner_for(triple: tuple[str, str, str]) -> str:
    encoded = "\x1f".join(triple).encode("utf-8")
    owner = int.from_bytes(hashlib.sha256(encoded).digest()[:8], "big") % len(OWNER_NAMES)
    return OWNER_NAMES[owner]


def split_edges(
    triples: Iterable[tuple[str, str, str]], handles: Mapping[tuple[str, str, str], int]
) -> dict[str, list[dict[str, Any]]]:
    owners: dict[str, list[dict[str, Any]]] = {owner: [] for owner in OWNER_NAMES}
    for triple in sorted(triples):
        source, relation, target = triple
        owners[owner_for(triple)].append(
            {
                "source": source,
                "relation": relation,
                "target": target,
                "evidence": handles[triple],
                "score": 1,
            }
        )
    return owners


def next_power_of_two(value: int) -> int:
    return 1 << max(0, (value - 1).bit_length())


def relation_partitioned_residual_plan(
    owner_edges: Mapping[str, list[dict[str, Any]]],
    entity_ids: Mapping[str, int],
    primary_types: Mapping[str, str],
    domains: Mapping[str, str],
    relation_count: int,
) -> dict[str, Any]:
    residual: dict[tuple[str, str], set[int]] = defaultdict(set)
    residual_keys = 0
    for owner, edges in owner_edges.items():
        for edge in edges:
            source = str(edge["source"])
            relation = str(edge["relation"])
            if primary_types[source] == domains[relation]:
                continue
            residual[(owner, relation)].add(entity_ids[source] + 1)
            residual_keys += 1

    candidates = [1 << power for power in range(0, 11)]
    plans = []
    tag_bits = max(1, len(entity_ids).bit_length())
    for buckets in candidates:
        worst = 0
        for tags in residual.values():
            loads: Counter[int] = Counter(bucket_of(tag, buckets) for tag in tags)
            worst = max(worst, max(loads.values(), default=0))
        slots = max(1, worst)
        logical_rows = relation_count * buckets
        padded_rows = next_power_of_two(logical_rows)
        width = len(OWNER_NAMES) * slots
        model_products = padded_rows * width + width * tag_bits
        plans.append(
            {
                "buckets": buckets,
                "slots": slots,
                "logical_rows": logical_rows,
                "padded_rows": padded_rows,
                "width": width,
                "model_products_per_address": model_products,
            }
        )
    chosen = min(plans, key=lambda row: (row["model_products_per_address"], row["padded_rows"]))
    return {
        "residual_key_occurrences": residual_keys,
        "nonempty_owner_relation_partitions": len(residual),
        "chosen": chosen,
        "candidates": plans,
    }


def capacity_bounds(
    owner_edges: Mapping[str, list[dict[str, Any]]], page_size: int
) -> dict[str, Any]:
    global_keys: Counter[tuple[str, str]] = Counter()
    owner_key_max = 0
    owner_source_max = 0
    owner_pages: dict[str, int] = {}
    owner_key_counts: dict[str, int] = {}
    for owner, edges in owner_edges.items():
        keys = Counter((str(edge["source"]), str(edge["relation"])) for edge in edges)
        sources = Counter(str(edge["source"]) for edge in edges)
        global_keys.update(keys)
        owner_key_max = max(owner_key_max, max(keys.values(), default=0))
        owner_source_max = max(owner_source_max, max(sources.values(), default=0))
        owner_pages[owner] = 1 + sum(math.ceil(count / page_size) for count in keys.values())
        owner_key_counts[owner] = len(keys)
    global_max = max(global_keys.values(), default=0)
    pages_per_key = max(1, math.ceil(owner_key_max / page_size))
    page_budget = max(2, next_power_of_two(max(owner_pages.values(), default=1)))
    return {
        "page_size": page_size,
        "pages_per_key": pages_per_key,
        "page_budget": page_budget,
        "frontier_per_owner": max(1, owner_key_max),
        "global_frontier": max(1, global_max),
        "max_owner_source_degree": max(1, owner_source_max),
        "owner_realized_pages_including_dummy": owner_pages,
        "owner_distinct_keys": owner_key_counts,
        "global_distinct_keys": len(global_keys),
        "global_max_key_degree": global_max,
    }


def closure_for_queries(
    triples: Iterable[tuple[str, str, str]], queries: list[dict[str, Any]]
) -> set[tuple[str, str, str]]:
    adjacency: dict[tuple[str, str], list[tuple[str, str, str]]] = defaultdict(list)
    for triple in triples:
        adjacency[(triple[0], triple[1])].append(triple)
    closure: set[tuple[str, str, str]] = set()
    for query in queries:
        first = adjacency[(str(query["source"]), str(query["relation_1"]))]
        closure.update(first)
        for _, _, middle in first:
            closure.update(adjacency[(middle, str(query["relation_2"]))])
    return closure


def make_queries(
    rows: list[dict[str, Any]], splits: tuple[str, ...] = ("val",)
) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    selected = [
        row for row in rows
        if row.get("split") in splits and row.get("path_equivalent")
    ]
    queries = [
        {
            "source": str(row["source_id"]),
            "relation_1": str(row["relation_1"]),
            "relation_2": str(row["relation_2"]),
        }
        for row in selected
    ]
    expected = [
        {
            "uid": row["uid"],
            "question": row["question"],
            "answer": row["answer"],
            "endpoint_ids": row["endpoint_ids"],
        }
        for row in selected
    ]
    return queries, expected


def build_scope(
    name: str,
    triples: list[tuple[str, str, str]],
    handles: Mapping[tuple[str, str, str], int],
    entity_ids: Mapping[str, int],
    primary_types: Mapping[str, str],
    all_domains: Mapping[str, str],
    queries: list[dict[str, str]],
    expected: list[dict[str, Any]],
    output: Path,
    page_size: int,
) -> dict[str, Any]:
    relations_used = sorted({relation for _, relation, _ in triples} | {
        relation for query in queries for relation in (query["relation_1"], query["relation_2"])
    })
    relation_ids = {relation: index for index, relation in enumerate(relations_used, start=1)}
    domains = {relation: all_domains[relation] for relation in relations_used}
    owner_edges = split_edges(triples, handles)
    bounds = capacity_bounds(owner_edges, page_size)
    residual = relation_partitioned_residual_plan(
        owner_edges, entity_ids, primary_types, domains, len(relation_ids)
    )
    chosen = residual["chosen"]
    candidate_slots = (
        bounds["global_frontier"]
        * len(OWNER_NAMES)
        * bounds["pages_per_key"]
        * bounds["page_size"]
    )
    config_document = {
        "owners": list(OWNER_NAMES),
        "entities": dict(entity_ids),
        "relations": relation_ids,
        "fanout_per_owner": bounds["max_owner_source_degree"],
        # KQA Pro's accepted rows have one gold endpoint. Do not widen storage
        # merely to manufacture a fourth padded output when a tiny correctness
        # fixture has only three public candidate slots.
        "top_k": min(4, candidate_slots),
        "score_bits": 20,
        "evidence_bits": 50,
        "field_prime": HE_SCALABLE_FIELD_PRIME,
        "deduplicate_terminal_answers": True,
        "relation_page_layout": {
            "page_size": bounds["page_size"],
            "pages_per_key": bounds["pages_per_key"],
            "page_budget": bounds["page_budget"],
            "frontier_per_owner": bounds["frontier_per_owner"],
            "global_frontier": bounds["global_frontier"],
            "directory_buckets": chosen["buckets"],
            "bucket_slots": chosen["slots"],
            "partition_residual_by_relation": True,
        },
        "type_block_layout": {
            "entity_types": dict(primary_types),
            "relation_domains": domains,
        },
    }
    scope_dir = output / name
    write_json(scope_dir / "config.json", config_document)
    write_json(scope_dir / "queries.json", queries)
    write_json(scope_dir / "expected_answers.json", expected)
    for owner, edges in owner_edges.items():
        write_json(scope_dir / f"{owner}.json", edges)

    config = RelationPageConfig.load(scope_dir / "config.json")
    owner_reports = {}
    for owner in OWNER_NAMES:
        layout = build_owner_page_layout(config, owner, owner_edges[owner])
        owner_reports[owner] = owner_layout_report(layout, config)
    global_bound = check_global_frontier(config, owner_edges)
    blocked_keys = 0
    residual_keys = 0
    for owner, edges in owner_edges.items():
        keys = {(str(edge["source"]), str(edge["relation"])) for edge in edges}
        for source, relation in keys:
            if primary_types[source] == domains[relation]:
                blocked_keys += 1
            else:
                residual_keys += 1
    report = {
        "scope": name,
        "fixture_semantics": {
            "full": "all frozen KQA Pro directed relation edges",
            "validation_closure": (
                "all two-hop paths reachable from the 21 public compatible "
                "validation queries; no answer-based edge selection"
            ),
            "compatible_closure": (
                "all two-hop paths reachable from all 199 public compatible "
                "train and validation queries; no answer-based edge selection"
            ),
        }.get(name, f"two-hop public-query workload closure: {name}"),
        "synthetic_federation": True,
        "owners": len(OWNER_NAMES),
        "entities_including_concept_nodes": len(entity_ids),
        "relations": len(relation_ids),
        "edges": len(triples),
        "owner_edge_counts": {owner: len(edges) for owner, edges in owner_edges.items()},
        "dense_directory_rows": config.dense_directory_rows,
        "type_blocked_rows": config.directory_rows,
        "type_block_max_width": config.type_blocks.max_block if config.type_blocks else None,
        "type_block_reduction": config.dense_directory_rows / config.directory_rows,
        "blocked_owner_keys": blocked_keys,
        "residual_owner_keys": residual_keys,
        "blocked_key_share": blocked_keys / (blocked_keys + residual_keys) if blocked_keys + residual_keys else 0.0,
        "capacity_bounds": bounds,
        "residual_capacity": residual,
        "owner_layouts": owner_reports,
        "global_frontier_check": global_bound,
        "cost_q1": paged_cost_estimate(config, 1),
        "cost_q21": paged_cost_estimate(config, 21),
        "warnings": [
            "Primary types and relation domains are derived from the public benchmark KB; deployment must use an externally public ontology.",
            "Capacity parameters are measured on this public benchmark fixture; private deployments need public bounds or a privacy-preserving capacity gate.",
            "Owner assignment is deterministic synthetic hashing, not real provenance.",
        ],
    }
    write_json(scope_dir / "capacity_report.json", report)
    return {"config": config, "owner_edges": owner_edges, "report": report, "dir": scope_dir}


def validate_queries(
    built: dict[str, Any],
    queries: list[dict[str, str]],
    expected: list[dict[str, Any]],
    handle_to_target: Mapping[int, str],
    evaluation_label: str = "KQA Pro snapshot-equivalent two-hop validation subset",
) -> dict[str, Any]:
    config: RelationPageConfig = built["config"]
    owner_edges = built["owner_edges"]
    records = []
    correct = 0
    for query, answer in zip(queries, expected, strict=True):
        oracle = evaluate_paged_cleartext(config, owner_edges, query)
        terminal_ids = [
            handle_to_target[item["right_evidence"]]
            for item in oracle
            if item["valid"] and item["right_evidence"] in handle_to_target
        ]
        wanted = sorted(str(value) for value in answer["endpoint_ids"])
        actual = sorted(set(terminal_ids))
        exact = actual == wanted
        correct += int(exact)
        records.append(
            {
                "uid": answer["uid"],
                "query": query,
                "expected_endpoint_ids": wanted,
                "actual_endpoint_ids": actual,
                "exact": exact,
                "oracle_output": oracle,
            }
        )
    report = {
        "evaluation_label": evaluation_label,
        "full_kqapro_accuracy": False,
        "queries": len(queries),
        "exact": correct,
        "exact_rate": correct / len(queries) if queries else 0.0,
        "records": records,
    }
    write_json(built["dir"] / "cleartext_validation.json", report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kb", type=Path, default=Path("data/kqa_pro/raw/kb.json"))
    parser.add_argument(
        "--compatible",
        type=Path,
        default=Path("data/kqa_pro/profile/kqapro_twohop_path_equivalent.jsonl"),
    )
    parser.add_argument("--out", type=Path, default=Path("data/kqa_pro/relation_fixture"))
    parser.add_argument("--full-page-size", type=int, default=32)
    args = parser.parse_args()
    if args.full_page_size < 1:
        parser.error("--full-page-size must be positive")

    kb = load_json(args.kb, dict)
    compatible = load_jsonl(args.compatible)
    queries, expected = make_queries(compatible, ("val",))
    all_queries, all_expected = make_queries(compatible, ("train", "val"))
    if len(queries) != 21:
        raise ValueError(f"expected 21 compatible validation queries, found {len(queries)}")
    if len(all_queries) != 199:
        raise ValueError(f"expected 199 compatible train+validation queries, found {len(all_queries)}")
    triples = directed_triples(kb)
    handles = {triple: index for index, triple in enumerate(triples, start=1)}
    handle_to_target = {handle: triple[2] for triple, handle in handles.items()}
    primary = public_primary_types(kb)
    entity_ids = contiguous_entity_ids(primary)
    domains = relation_domains(triples, primary)
    closure = sorted(closure_for_queries(triples, queries))
    compatible_closure = sorted(closure_for_queries(triples, all_queries))

    full = build_scope(
        "full", triples, handles, entity_ids, primary, domains, queries, expected,
        args.out, args.full_page_size,
    )
    correctness = build_scope(
        "validation_closure", closure, handles, entity_ids, primary, domains,
        queries, expected, args.out, 1,
    )
    validation = validate_queries(correctness, queries, expected, handle_to_target)
    compatible = build_scope(
        "compatible_closure", compatible_closure, handles, entity_ids, primary,
        domains, all_queries, all_expected, args.out, 1,
    )
    compatible_validation = validate_queries(
        compatible,
        all_queries,
        all_expected,
        handle_to_target,
        "KQA Pro snapshot-equivalent two-hop compatible train+validation subset",
    )
    manifest = {
        "dataset": "KQA Pro",
        "evaluation_label": "KQA Pro snapshot-equivalent two-hop validation subset",
        "full_graph": full["report"],
        "validation_closure": correctness["report"],
        "compatible_closure": compatible["report"],
        "cleartext_validation": {
            key: value for key, value in validation.items() if key != "records"
        },
        "compatible_cleartext_validation": {
            key: value for key, value in compatible_validation.items() if key != "records"
        },
        "methodological_separation": (
            "Use full/capacity_report.json for scalability claims and "
            "validation_closure/cleartext_validation.json only for controlled correctness."
        ),
    }
    write_json(args.out / "manifest.json", manifest)
    print(
        f"full graph: {len(triples):,} edges; validation closure: {len(closure):,} "
        f"edges; compatible closure: {len(compatible_closure):,} edges"
    )
    print(f"cleartext validation: {validation['exact']}/{validation['queries']} exact")
    print(
        "compatible train+validation: "
        f"{compatible_validation['exact']}/{compatible_validation['queries']} exact"
    )
    print(f"wrote {args.out / 'manifest.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
