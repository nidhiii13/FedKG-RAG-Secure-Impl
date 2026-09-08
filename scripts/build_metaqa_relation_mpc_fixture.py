#!/usr/bin/env python3
"""Build an answer-independent MetaQA fixture for native relation-paged MPC.

The query relation pair is inferred from the public question template and
oriented using the knowledge graph, without consulting the supplied answers.
By default, all directed keys in the MetaQA graph are retained, subject only to
the stated public per-key bound.  Optional public relation buckets can be used
to produce smaller circuits while retaining more than one possible relation
pair in each bucket.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from doram_t2_3pc.config import HE_SCALABLE_FIELD_PRIME  # noqa: E402
from doram_t2_3pc.relation_pages import (  # noqa: E402
    RelationPageConfig,
    build_owner_page_layout,
    check_global_frontier,
    evaluate_paged_cleartext,
    owner_layout_report,
)
from scripts.build_kqapro_relation_fixture import (  # noqa: E402
    relation_partitioned_residual_plan,
)

OWNERS = ("owner_0", "owner_1", "owner_2")
BASE_RELATIONS = {
    "directed_by", "written_by", "starred_actors", "release_year",
    "in_language", "has_genre", "has_tags", "has_imdb_rating",
    "has_imdb_votes",
}
TARGET_TYPES = {
    "directed_by": "director",
    "written_by": "writer",
    "starred_actors": "actor",
    "release_year": "release-year",
    "in_language": "language",
    "has_genre": "genre",
    "has_tags": "tag",
    "has_imdb_rating": "imdb-rating",
    "has_imdb_votes": "imdb-votes",
}
BRACKETED_ENTITY = re.compile(r"\[([^\]]+)\]")


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def contains_any(text: str, phrases: Iterable[str]) -> bool:
    return any(phrase in text for phrase in phrases)


def template_relations(question: str) -> tuple[str, str] | None:
    """Infer the two base relations from a MetaQA template, without answers."""
    text = question.casefold()
    masked = BRACKETED_ENTITY.sub("[entity]", text)
    if contains_any(text, (
        "share actors", "same actor", "same movie", "also appear", "co-star",
        "acted together", "starred together",
    )):
        return "starred_actors", "starred_actors"
    if contains_any(text, (
        "share directors", "same director", "also directed", "co-director",
        "co-directed", "also the director", "directed films together",
        "directed movies together",
    )):
        return "directed_by", "directed_by"
    if contains_any(text, (
        "share writers", "same screenwriter", "share the screenwriter", "also wrote",
        "co-wrote", "co-writer", "wrote movies together", "wrote films together",
        "written together",
    )):
        return "written_by", "written_by"

    # A relation stated after the topic entity describes how that entity
    # reaches the intermediate movie. Check this before an answer phrase such
    # as "director of [actor] starred movies".
    if contains_any(masked, ("[entity] written", "[entity] wrote", "[entity] screenwriter")):
        first = "written_by"
    elif "[entity] directed" in masked:
        first = "directed_by"
    elif contains_any(masked, ("[entity] starred", "[entity] acted")):
        first = "starred_actors"
    elif contains_any(masked, (
        "written by [entity]", "writer [entity]", "writer of [entity]",
    )):
        first = "written_by"
    elif contains_any(masked, (
        "directed by [entity]", "director [entity]", "director of [entity]",
    )):
        first = "directed_by"
    elif contains_any(masked, (
        "starred by [entity]", "acted by [entity]", "actor [entity]",
        "actor of [entity]",
    )):
        first = "starred_actors"
    else:
        return None

    if contains_any(text, ("language", "languages", "spoken")):
        second = "in_language"
    elif contains_any(text, ("tag", "tags")):
        second = "has_tags"
    elif contains_any(text, ("imdb rating", "ratings", "rating")):
        second = "has_imdb_rating"
    elif contains_any(text, ("imdb votes", "votes", "vote")):
        second = "has_imdb_votes"
    elif contains_any(text, ("genre", "genres", "types", "type")):
        second = "has_genre"
    elif contains_any(text, ("release", "released", "when", "year", "years")):
        second = "release_year"
    elif (
        text.startswith(("who directed", "which person directed", "who are the directors"))
        or contains_any(text, ("directed by who", "listed as director", "director is who"))
    ):
        second = "directed_by"
    elif (
        text.startswith(("who wrote", "which person wrote", "who are the writers"))
        or contains_any(text, ("written by who", "listed as screenwriter", "screenwriter is who"))
    ):
        second = "written_by"
    elif contains_any(text, ("starred", "actors", "actor", "person", "appeared", "who")):
        second = "starred_actors"
    else:
        return None
    return first, second


def load_directed_graph(kb_path: Path) -> tuple[list[tuple[str, str, str]], dict[tuple[str, str], list[str]]]:
    directed: set[tuple[str, str, str]] = set()
    for number, line in enumerate(kb_path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        parts = tuple(part.strip() for part in line.split("|"))
        if len(parts) != 3:
            raise ValueError(f"{kb_path}:{number} is not subject|relation|object")
        source, relation, target = parts
        if relation not in BASE_RELATIONS:
            raise ValueError(f"unexpected MetaQA relation {relation!r}")
        directed.add((source, relation, target))
        directed.add((target, f"{relation}_inverse", source))
    triples = sorted(directed)
    adjacency: dict[tuple[str, str], list[str]] = defaultdict(list)
    for source, relation, target in triples:
        adjacency[(source, relation)].append(target)
    return triples, adjacency


def orient_relation(
    frontier: set[str], base_relation: str, adjacency: dict[tuple[str, str], list[str]]
) -> tuple[str, set[str]] | None:
    candidates = (base_relation, f"{base_relation}_inverse")
    scored = []
    for relation in candidates:
        targets = {
            target
            for source in frontier
            for target in adjacency.get((source, relation), [])
        }
        scored.append((len(targets), relation, targets))
    count, relation, targets = max(scored, key=lambda item: (item[0], item[1]))
    return (relation, targets) if count else None


def parse_question(
    question: str, adjacency: dict[tuple[str, str], list[str]]
) -> tuple[dict[str, str] | None, str]:
    entity_match = BRACKETED_ENTITY.search(question)
    if entity_match is None:
        return None, "missing bracketed topic entity"
    bases = template_relations(question)
    if bases is None:
        return None, "unsupported question template"
    source = entity_match.group(1).strip()
    first = orient_relation({source}, bases[0], adjacency)
    if first is None:
        return None, "first relation has no edge from the topic entity"
    relation_1, middle = first
    second = orient_relation(middle, bases[1], adjacency)
    if second is None:
        return None, "second relation has no edge from the first-hop frontier"
    relation_2, _ = second
    return {
        "source": source,
        "relation_1": relation_1,
        "relation_2": relation_2,
    }, "parsed"


def load_questions(
    qa_path: Path,
    adjacency: dict[tuple[str, str], list[str]],
) -> tuple[list[dict[str, Any]], Counter[str]]:
    compatible = []
    rejected: Counter[str] = Counter()
    for index, line in enumerate(qa_path.read_text(encoding="utf-8").splitlines()):
        if not line.strip():
            continue
        question, answers = line.split("\t", 1)
        query, status = parse_question(question, adjacency)
        if query is None:
            rejected[status] += 1
            continue
        compatible.append({
            "index": index,
            "question": question.replace("[", "").replace("]", ""),
            "raw_question": question,
            "answers": answers.split("|"),
            "query": query,
        })
    return compatible, rejected


def owner_for_source(source: str) -> str:
    value = int.from_bytes(hashlib.sha256(source.encode("utf-8")).digest()[:8], "big")
    return OWNERS[value % len(OWNERS)]


def relation_domain(relation: str) -> str:
    if relation.endswith("_inverse"):
        return TARGET_TYPES[relation[: -len("_inverse")]]
    return "movie"


def primary_types(
    triples: Iterable[tuple[str, str, str]], entities: Iterable[str]
) -> dict[str, str]:
    """Choose a deterministic public primary type from the public benchmark KG."""
    counts: dict[str, Counter[str]] = defaultdict(Counter)
    incoming: dict[str, Counter[str]] = defaultdict(Counter)
    for source, relation, target in triples:
        counts[source][relation_domain(relation)] += 1
        if relation.endswith("_inverse"):
            incoming[target]["movie"] += 1
        else:
            incoming[target][TARGET_TYPES[relation]] += 1
    return {
        entity: max(
            sorted(counts[entity] or incoming[entity]),
            key=lambda value: ((counts[entity] or incoming[entity])[value], value),
        )
        for entity in entities
    }


def build_fixture(args: argparse.Namespace) -> dict[str, Any]:
    triples, adjacency = load_directed_graph(args.kb)
    compatible, rejected = load_questions(args.qa, adjacency)
    if args.questions < 0:
        raise ValueError("--questions must be non-negative")
    if args.question_indices is not None:
        indices = json.loads(args.question_indices.read_text(encoding="utf-8"))
        if not isinstance(indices, list) or not all(isinstance(value, int) for value in indices):
            raise ValueError("--question-indices must contain a JSON list of integers")
        if len(indices) != len(set(indices)):
            raise ValueError("--question-indices contains duplicate indices")
        by_index = {row["index"]: row for row in compatible}
        missing = [value for value in indices if value not in by_index]
        if missing:
            raise ValueError(
                f"{len(missing)} requested question indices are not compatible: {missing[:5]}"
            )
        selected = [by_index[value] for value in indices]
    else:
        requested = len(compatible) if args.questions == 0 else args.questions
        if requested > len(compatible):
            raise ValueError(
                f"requested {requested} questions but only {len(compatible)} templates parsed"
            )
        selected = random.Random(args.seed).sample(compatible, requested)

    relation_allowlist = None
    if args.relation_allowlist is not None:
        raw_allowlist = json.loads(args.relation_allowlist.read_text(encoding="utf-8"))
        if not isinstance(raw_allowlist, list) or not all(
            isinstance(value, str) and value for value in raw_allowlist
        ):
            raise ValueError("--relation-allowlist must contain a JSON list of strings")
        relation_allowlist = set(raw_allowlist)
        graph_relations = {relation for _, relation, _ in triples}
        unknown = sorted(relation_allowlist - graph_relations)
        if unknown:
            raise ValueError(f"unknown relations in --relation-allowlist: {unknown}")
        missing_query_relations = sorted({
            relation
            for row in selected
            for relation in (row["query"]["relation_1"], row["query"]["relation_2"])
            if relation not in relation_allowlist
        })
        if missing_query_relations:
            raise ValueError(
                "relation allowlist does not cover the selected queries: "
                f"{missing_query_relations}"
            )
        triples = [
            triple for triple in triples if triple[1] in relation_allowlist
        ]

    by_key: dict[tuple[str, str], list[str]] = defaultdict(list)
    for source, relation, target in triples:
        by_key[(source, relation)].append(target)
    retained: list[tuple[str, str, str]] = []
    clipped_edges = 0
    clipped_keys = 0
    maximum_degree = 0
    for (source, relation), targets in sorted(by_key.items()):
        unique_targets = sorted(set(targets))
        maximum_degree = max(maximum_degree, len(unique_targets))
        if len(unique_targets) > args.bound:
            clipped_keys += 1
            clipped_edges += len(unique_targets) - args.bound
        retained.extend(
            (source, relation, target) for target in unique_targets[: args.bound]
        )

    # Assign handles globally before splitting by owner, avoiding owner-specific
    # handle ranges. Determinism is an experimental reproducibility control.
    handle_order = list(retained)
    random.Random(args.seed).shuffle(handle_order)
    handles = {triple: index for index, triple in enumerate(handle_order, 1)}
    handle_to_target = {handles[triple]: triple[2] for triple in retained}
    owner_edges: dict[str, list[dict[str, Any]]] = {owner: [] for owner in OWNERS}
    for source, relation, target in retained:
        owner_edges[owner_for_source(source)].append({
            "source": source,
            "relation": relation,
            "target": target,
            "evidence": handles[(source, relation, target)],
            "score": 1,
        })

    if args.base_fixture is not None:
        if relation_allowlist is None:
            raise ValueError("--base-fixture requires --relation-allowlist")
        base_config = json.loads(
            (args.base_fixture / "config.json").read_text(encoding="utf-8")
        )
        entity_ids = {
            str(entity): int(identifier)
            for entity, identifier in base_config["entities"].items()
        }
        entity_types = {
            str(entity): str(kind)
            for entity, kind in base_config["type_block_layout"]["entity_types"].items()
        }
        owner_edges = {}
        for owner in OWNERS:
            base_edges = json.loads(
                (args.base_fixture / f"{owner}.json").read_text(encoding="utf-8")
            )
            owner_edges[owner] = [
                edge for edge in base_edges if edge["relation"] in relation_allowlist
            ]
        retained = [
            (edge["source"], edge["relation"], edge["target"])
            for owner in OWNERS
            for edge in owner_edges[owner]
        ]
        handle_to_target = {
            int(edge["evidence"]): str(edge["target"])
            for owner in OWNERS
            for edge in owner_edges[owner]
        }
        entities = sorted(entity_ids, key=entity_ids.get)
    else:
        entities = sorted(
            {source for source, _, _ in triples} | {target for _, _, target in triples}
        )
        entity_types = primary_types(triples, entities)
        ordered_entities = sorted(entities, key=lambda entity: (entity_types[entity], entity))
        entity_ids = {entity: index for index, entity in enumerate(ordered_entities, 1)}
    relations = sorted({relation for _, relation, _ in triples})
    relation_ids = {relation: index for index, relation in enumerate(relations, 1)}
    relation_domains = {relation: relation_domain(relation) for relation in relations}
    key_counts = {
        owner: len({(edge["source"], edge["relation"]) for edge in edges})
        for owner, edges in owner_edges.items()
    }
    page_layout = {
        "page_size": args.bound,
        "pages_per_key": 1,
        "page_budget": max(key_counts.values()) + 1,
        "frontier_per_owner": args.bound,
        "global_frontier": args.bound,
    }
    residual_plan = None
    if not args.dense_directory:
        residual_plan = relation_partitioned_residual_plan(
            owner_edges,
            entity_ids,
            entity_types,
            relation_domains,
            len(relation_ids),
        )
        chosen = residual_plan["chosen"]
        page_layout.update({
            "directory_buckets": chosen["buckets"],
            "bucket_slots": chosen["slots"],
            "partition_residual_by_relation": True,
        })
    config_doc = {
        "owners": list(OWNERS),
        "entities": entity_ids,
        "relations": relation_ids,
        "fanout_per_owner": args.bound,
        "top_k": args.top_k,
        "score_bits": 20,
        "evidence_bits": 50,
        "field_prime": HE_SCALABLE_FIELD_PRIME,
        "deduplicate_terminal_answers": True,
        "relation_page_layout": page_layout,
    }
    if not args.dense_directory:
        config_doc["type_block_layout"] = {
            "entity_types": entity_types,
            "relation_domains": relation_domains,
        }
    args.out.mkdir(parents=True, exist_ok=True)
    write_json(args.out / "config.json", config_doc)
    for owner, edges in owner_edges.items():
        write_json(args.out / f"{owner}.json", edges)
    write_json(args.out / "queries.json", [row["query"] for row in selected])
    write_json(args.out / "expected_answers.json", [
        {
            "index": row["index"],
            "question": row["question"],
            "answers": row["answers"],
        }
        for row in selected
    ])

    config = RelationPageConfig.load(args.out / "config.json")
    prepared_layouts = {
        owner: build_owner_page_layout(config, owner, owner_edges[owner])
        for owner in OWNERS
    }
    owner_reports = {
        owner: owner_layout_report(prepared_layouts[owner], config)
        for owner in OWNERS
    }
    frontier_check = check_global_frontier(config, owner_edges)
    oracle_records = []
    evidence_hits = 0
    for row in selected:
        output = evaluate_paged_cleartext(
            config,
            owner_edges,
            row["query"],
            prepared_layouts=prepared_layouts,
        )
        terminals = {
            handle_to_target[item["right_evidence"]]
            for item in output
            if item["valid"] and item["right_evidence"] in handle_to_target
        }
        wanted = set(row["answers"])
        hit = bool(terminals & wanted)
        evidence_hits += int(hit)
        oracle_records.append({
            "index": row["index"],
            "query": row["query"],
            "gold_answers": row["answers"],
            "retrieved_terminal_entities": sorted(terminals),
            "evidence_hit": hit,
            "oracle_output": output,
        })
    graph_scope = (
        "complete directed key set"
        if relation_allowlist is None
        else f"public {args.public_scope_label or 'relation bucket'}"
    )
    oracle = {
        "evaluation_label": (
            "MetaQA two-hop test questions with answer-independent template parsing; "
            f"{graph_scope} clipped to public bound {args.bound}"
        ),
        "query_selection_uses_gold_answers": False,
        "queries": len(selected),
        "evidence_hits": evidence_hits,
        "evidence_hit_rate": evidence_hits / len(selected) if selected else 0.0,
        "records": oracle_records,
    }
    write_json(args.out / "cleartext_validation.json", oracle)
    capacity = {
        "fixture_semantics": (
            (
                "all MetaQA entities, relations and directed source-relation keys"
                if relation_allowlist is None
                else (
                    f"MetaQA directed keys in the public {args.public_scope_label or 'relation bucket'}; "
                    "the exact query relation pair remains secret within the bucket"
                )
            )
            + f"; each key retains its first {args.bound} lexicographically ordered targets"
        ),
        "query_selection": (
            "seeded sample from templates parsed without consulting gold answers"
        ),
        "seed": args.seed,
        "test_questions_total": sum(1 for line in args.qa.read_text(encoding="utf-8").splitlines() if line.strip()),
        "compatible_templates": len(compatible),
        "template_rejections": dict(rejected),
        "selected_queries": len(selected),
        "selected_question_indices": [row["index"] for row in selected],
        "public_scope_label": args.public_scope_label,
        "public_relation_allowlist": sorted(relation_allowlist) if relation_allowlist else None,
        "synthetic_ownership": "SHA-256(source) modulo 3",
        "entities": len(entities),
        "relations": len(relations),
        "directed_edges_before_bound": len(triples),
        "directed_edges_after_bound": len(retained),
        "maximum_unclipped_key_degree": maximum_degree,
        "clipped_keys": clipped_keys,
        "clipped_edges": clipped_edges,
        "public_per_key_bound": args.bound,
        "dense_directory_rows_including_dummy_entity_row": config.dense_directory_rows,
        "actual_directory_rows": config.directory_rows,
        "directory_optimisation": (
            "dense" if args.dense_directory else "type-blocked plus relation-partitioned residual"
        ),
        "dense_to_actual_row_reduction": config.dense_directory_rows / config.directory_rows,
        "maximum_public_type_block_width": (
            config.type_blocks.max_block if config.type_blocks else None
        ),
        "residual_capacity": residual_plan,
        "owner_key_counts": key_counts,
        "owner_layouts": owner_reports,
        "global_frontier_check": frontier_check,
        "privacy_scope": (
            (
                "one full MetaQA relation ontology is public"
                if relation_allowlist is None
                else f"the public workload class is {args.public_scope_label or 'a relation bucket'}"
            )
            + "; source and both exact relations remain secret-shared"
        ),
        "warnings": [
            "MetaQA has no owner provenance; ownership is synthetic.",
            "The public per-key bound clips high-degree keys before owner-local preparation.",
            "Deterministic handles are for reproducibility, not deployment randomness.",
        ],
    }
    write_json(args.out / "capacity_report.json", capacity)
    return {"capacity": capacity, "oracle": {k: v for k, v in oracle.items() if k != "records"}}


def parse_args() -> argparse.Namespace:
    simgrag = ROOT.parent / "SimGRAG/data/raw/metaQA"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kb", type=Path, default=simgrag / "kb.txt")
    parser.add_argument("--qa", type=Path, default=simgrag / "2-hop/vanilla/qa_test.txt")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--questions", type=int, default=1000,
        help="seeded compatible-template sample size; use 0 for every compatible template",
    )
    parser.add_argument("--bound", type=int, default=8)
    parser.add_argument("--top-k", type=int, default=4)
    parser.add_argument("--seed", type=int, default=4242)
    parser.add_argument(
        "--question-indices",
        type=Path,
        help="JSON list of compatible source-file row indices to use instead of sampling",
    )
    parser.add_argument(
        "--relation-allowlist",
        type=Path,
        help="JSON list of public relations retained in this workload bucket",
    )
    parser.add_argument(
        "--public-scope-label",
        help="human-readable public workload class recorded in the fixture metadata",
    )
    parser.add_argument(
        "--base-fixture",
        type=Path,
        help=(
            "preserve entity identifiers and evidence handles from this full fixture "
            "when constructing a public relation bucket"
        ),
    )
    parser.add_argument(
        "--dense-directory",
        action="store_true",
        help="disable the hybrid public-ontology optimisation for a dense ablation",
    )
    args = parser.parse_args()
    if args.bound < 1:
        parser.error("--bound must be positive")
    if args.top_k < 1:
        parser.error("--top-k must be positive")
    return args


if __name__ == "__main__":
    print(json.dumps(build_fixture(parse_args()), indent=2))
