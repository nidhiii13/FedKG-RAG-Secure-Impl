#!/usr/bin/env python3
"""Build a 100k-entity/160k-record controlled fixture from RoG-CWQ.

This is a systems-scale fixture, not a representative retrieval-quality sample.
It starts from the deduplicated held-out RoG-CWQ snapshot, selects six declared
relations, constructs a deterministic 100,000-entity induced slice, and retains
exactly 160,000 genuine snapshot records.  One relation is stored in the inverse
orientation used by the query adapter; every such record maps one-to-one to a
``common.topic.image`` triple in the source snapshot.

The included query is an actual strict dependent two-hop CWQ question.  No gold
answer is used to select filler records.  Synthetic ownership remains necessary
because CWQ has no institutional owner labels.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from doram_t2_3pc.config import HE_SCALABLE_FIELD_PRIME  # noqa: E402
from doram_t2_3pc.evidence_handles import allocate_owner_blind_handles  # noqa: E402
from doram_t2_3pc.relation_pages import (  # noqa: E402
    RelationPageConfig,
    check_global_frontier,
    evaluate_paged_cleartext,
)


ENTITY_COUNT = 100_000
EDGE_COUNT = 160_000
OWNER_COUNT = 3
KEY_CAP = 3
SEED = 4242

FORWARD_RELATIONS = {
    "common.topic.notable_types",
    "freebase.valuenotation.is_reviewed",
    "film.film.starring",
    "film.performance.film",
    "people.person.profession",
    "common.topic.image",
}
IMAGE = "common.topic.image"
IMAGE_INVERSE = "common.topic.image_inverse"

QUERY = {
    "source": "Flag of Calabria",
    "relation_1": IMAGE_INVERSE,
    "relation_2": "common.topic.notable_types",
}
QUESTION = 'What\'s the topic of the picture "Flag of Calabria Italy"?'
GROUNDTRUTHS = ["Italian region"]
MANDATORY_EDGES = {
    ("Flag of Calabria", IMAGE_INVERSE, "Calabria"),
    ("Calabria", "common.topic.notable_types", "Italian region"),
}


def stable_hash(value: object) -> int:
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return int.from_bytes(hashlib.sha256(encoded.encode("utf-8")).digest(), "big")


def load_candidates(raw: Path) -> set[tuple[str, str, str]]:
    edges: set[tuple[str, str, str]] = set()
    for split in ("test", "validation"):
        source = raw / f"rog_cwq_{split}.jsonl"
        with source.open(encoding="utf-8") as stream:
            for line in stream:
                if not line.strip():
                    continue
                for raw_head, raw_relation, raw_tail in json.loads(line).get("graph", []):
                    head = str(raw_head)
                    relation = str(raw_relation)
                    tail = str(raw_tail)
                    if relation not in FORWARD_RELATIONS:
                        continue
                    if relation == IMAGE:
                        edges.add((tail, IMAGE_INVERSE, head))
                    else:
                        edges.add((head, relation, tail))
    if not MANDATORY_EDGES <= edges:
        raise RuntimeError("the preserved CWQ query path is absent from the snapshot")
    return edges


def select_nodes(edges: set[tuple[str, str, str]]) -> set[str]:
    adjacency: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    for edge in edges:
        adjacency[edge[0]].append(edge)
        adjacency[edge[2]].append(edge)

    chosen = {node for edge in MANDATORY_EDGES for node in (edge[0], edge[2])}
    ranked = sorted(adjacency, key=lambda node: (-len(adjacency[node]), node))
    for node in ranked:
        required = {
            endpoint
            for edge in adjacency[node]
            for endpoint in (edge[0], edge[2])
        } - chosen
        if len(chosen) + len(required) <= ENTITY_COUNT:
            chosen.update(required)
        if len(chosen) == ENTITY_COUNT:
            break
    if len(chosen) < ENTITY_COUNT:
        for node in sorted(adjacency):
            chosen.add(node)
            if len(chosen) == ENTITY_COUNT:
                break
    if len(chosen) != ENTITY_COUNT:
        raise RuntimeError(f"could select only {len(chosen):,} entities")
    return chosen


def select_edges(
    candidates: set[tuple[str, str, str]], nodes: set[str]
) -> list[tuple[str, str, str]]:
    grouped: dict[tuple[str, str], list[tuple[str, str, str]]] = defaultdict(list)
    for edge in candidates:
        if edge[0] in nodes and edge[2] in nodes:
            grouped[(edge[0], edge[1])].append(edge)

    selected: list[tuple[str, str, str]] = []
    third_choices: list[tuple[str, str, str]] = []
    for key in sorted(grouped):
        required = sorted(edge for edge in MANDATORY_EDGES if edge[:2] == key)
        remainder = sorted(edge for edge in grouped[key] if edge not in required)
        ordered = required + remainder
        selected.extend(ordered[:2])
        if len(ordered) >= 3:
            third_choices.append(ordered[2])

    if len(selected) > EDGE_COUNT:
        raise RuntimeError("two-record base exceeds the requested edge count")
    need = EDGE_COUNT - len(selected)
    third_choices.sort(key=lambda edge: (stable_hash([SEED, *edge]), edge))
    if need > len(third_choices):
        raise RuntimeError(
            f"only {len(selected) + len(third_choices):,} records remain at cap {KEY_CAP}"
        )
    selected.extend(third_choices[:need])
    selected.sort()

    degrees = Counter((head, relation) for head, relation, _ in selected)
    active_nodes = {node for edge in selected for node in (edge[0], edge[2])}
    if len(selected) != EDGE_COUNT or max(degrees.values()) > KEY_CAP:
        raise AssertionError("selected graph violates its declared dimensions")
    if len(active_nodes) != ENTITY_COUNT:
        raise AssertionError(
            f"selected edges contain {len(active_nodes):,}, not {ENTITY_COUNT:,}, active entities"
        )
    if not MANDATORY_EDGES <= set(selected):
        raise AssertionError("selection removed the real CWQ query path")
    return selected


def write_json(path: Path, value: object) -> None:
    with path.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False)
        stream.write("\n")


def build(raw: Path, output: Path) -> dict[str, object]:
    output.mkdir(parents=True, exist_ok=False)
    candidates = load_candidates(raw)
    nodes = select_nodes(candidates)
    edges = select_edges(candidates, nodes)

    entity_order = sorted(nodes)
    relation_order = sorted({relation for _, relation, _ in edges})
    entities = {name: index + 1 for index, name in enumerate(entity_order)}
    relations = {name: index + 1 for index, name in enumerate(relation_order)}

    plain_rows = [
        {
            "source": head,
            "relation": relation,
            "target": tail,
            "evidence": 1,
            "score": 1,
        }
        for head, relation, tail in edges
    ]
    handled = allocate_owner_blind_handles(
        plain_rows, evidence_bits=50, rng=random.Random(SEED)
    )
    owner_rows: list[list[dict[str, object]]] = [[] for _ in range(OWNER_COUNT)]
    for row in handled:
        owner = stable_hash(str(row["source"])) % OWNER_COUNT
        owner_rows[owner].append(row)
    for rows in owner_rows:
        rows.sort(key=lambda row: (
            str(row["source"]), str(row["relation"]), str(row["target"]),
            int(row["evidence"]), int(row["score"]),
        ))

    owner_keys = [len({(row["source"], row["relation"]) for row in rows})
                  for rows in owner_rows]
    config = {
        "owners": [f"owner_{index}" for index in range(OWNER_COUNT)],
        "entities": entities,
        "relations": relations,
        "fanout_per_owner": KEY_CAP,
        "top_k": 4,
        "field_prime": HE_SCALABLE_FIELD_PRIME,
        "relation_page_layout": {
            "page_size": KEY_CAP,
            "pages_per_key": 1,
            "page_budget": max(owner_keys) + 1,
            "frontier_per_owner": KEY_CAP,
            "global_frontier": KEY_CAP,
        },
    }
    write_json(output / "config.json", config)
    write_json(output / "queries.json", [QUERY])
    for owner, rows in enumerate(owner_rows):
        write_json(output / f"owner_{owner}.json", rows)

    loaded = RelationPageConfig.load(output / "config.json")
    owners = {f"owner_{index}": rows for index, rows in enumerate(owner_rows)}
    frontier = check_global_frontier(loaded, owners)
    oracle = evaluate_paged_cleartext(loaded, owners, QUERY)
    write_json(output / "cleartext_validation.json", {
        "evaluation_label": "controlled 100k-entity/160k-record RoG-CWQ scale fixture",
        "records": [{
            "uid": "WebQTrn-724_d133cd1308f3fd8e12b6e2eb7acbc859",
            "question": QUESTION,
            "groundtruths": GROUNDTRUTHS,
            "query": QUERY,
            "oracle_output": oracle,
        }],
    })

    manifest: dict[str, object] = {
        "kind": "controlled-rog-cwq-relation-paged-160k",
        "scope_warning": (
            "Deterministically density-selected held-out RoG-CWQ slice for systems-scale "
            "testing; not an unbiased retrieval-quality sample. Ownership is synthetic."
        ),
        "entities": len(entities),
        "active_entities": len({node for edge in edges for node in (edge[0], edge[2])}),
        "stored_records": len(edges),
        "source_snapshot_triples": len(edges),
        "relations": relation_order,
        "owners": OWNER_COUNT,
        "owner_edge_counts": [len(rows) for rows in owner_rows],
        "owner_key_counts": owner_keys,
        "maximum_federation_key_degree": max(
            Counter((h, r) for h, r, _ in edges).values()
        ),
        "directory_rows_including_dummy_entity": loaded.directory_rows,
        "query": QUERY,
        "question": QUESTION,
        "groundtruths": GROUNDTRUTHS,
        "global_frontier_check": frontier,
        "oracle_output": oracle,
        "inverse_record_provenance": (
            "Every common.topic.image_inverse record is the reversed orientation of a "
            "genuine common.topic.image triple in the held-out RoG-CWQ snapshot."
        ),
    }
    write_json(output / "fixture_manifest.json", manifest)
    write_json(output / "capacity_report.json", {
        "fixture_semantics": (
            "controlled density-selected slice of the held-out RoG-CWQ snapshot; "
            "100,000 active entities, 160,000 genuine snapshot-derived records, "
            "six relations, one real strict two-hop CWQ query, and synthetic "
            "three-owner subject-hash partitioning"
        ),
        "entities": len(entities),
        "relations": len(relations),
        "edges_kept": len(edges),
        "bound": KEY_CAP,
        "top_k": config["top_k"],
        "global_frontier_check": frontier,
    })
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, default=ROOT / "data/cwq/raw")
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(build(args.raw, args.output_dir), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
