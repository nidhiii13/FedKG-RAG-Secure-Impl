#!/usr/bin/env python3
"""Prepare a bounded MetaQA exact-lookup instance for MP-SPDZ.

This script intentionally creates a small, fixed-size MPC input instance. It is
the first step toward the client-excluded N-party MPC design, not a full private
KG traversal implementation.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import pickle
from pathlib import Path


FIELD_MASK = (1 << 61) - 1
UNKNOWN = "UNKNOWN"
FORWARD_STARRED_ACTOR_RELATIONS = {
    "acted by",
    "is acted by",
    "appeared by",
    "has actor",
    "has actors",
    "have actor",
    "have actors",
    "is starred by",
    "starred by",
    "starred_actors",
}
REVERSE_STARRED_ACTOR_RELATIONS = {
    "act in",
    "acted in",
    "actor of",
    "appear in",
    "appears in",
    "star in",
    "star of",
    "starred in",
}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _load_party(path: Path) -> tuple[dict, dict | None]:
    with path.open("rb") as handle:
        payload = pickle.load(handle)
    return payload["graph"], payload.get("types")


def _canonical_text(value: str) -> str:
    return " ".join(str(value).strip().lower().split())


def _is_unknown(value: str) -> bool:
    return _canonical_text(value).startswith("unknown")


def _normalize_relation(relation: str, *, semantic_relations: bool) -> tuple[str, str]:
    if not semantic_relations:
        return relation, "forward"
    canonical = _canonical_text(relation)
    if canonical in FORWARD_STARRED_ACTOR_RELATIONS:
        return "starred_actors", "forward"
    if canonical in REVERSE_STARRED_ACTOR_RELATIONS:
        return "starred_actors", "reverse"
    return relation, "forward"


def _hmac_int(setup_key: str, namespace: str, value: str) -> int:
    message = f"{namespace}:{_canonical_text(value)}".encode("utf-8")
    digest = hmac.new(setup_key.encode("utf-8"), message, hashlib.sha256).digest()
    return int.from_bytes(digest[:8], "big") & FIELD_MASK


def _parse_edge(value: str) -> tuple[str, str, str]:
    parts = [part.strip() for part in value.split("|")]
    if len(parts) != 3:
        raise argparse.ArgumentTypeError("edge must be SOURCE|RELATION|TARGET")
    return parts[0], parts[1], parts[2]


def _load_manifest(path: Path) -> dict:
    with path.open() as handle:
        return json.load(handle)


def _party_edges(
    graph: dict,
    setup_key: str,
    source_filter: str,
    relation_filter: str,
    direction: str,
    candidate_slots: dict[str, int],
    rows_per_party: int,
) -> list[tuple[int, int, int, int]]:
    source_id = _hmac_int(setup_key, "entity", source_filter)
    relation_id = _hmac_int(setup_key, "relation", relation_filter)
    rows: list[tuple[int, int, int, int]] = []

    # For this first bounded prototype, we include rows that are useful for the
    # selected one-hop query plus padding. A production MPC retrieval circuit
    # would use fixed public tables or padded private tables independent of one
    # query instance.
    for source, adjacency in graph.items():
        for relation, targets in adjacency.items():
            if _canonical_text(relation) != _canonical_text(relation_filter):
                continue
            for target in targets:
                if direction == "reverse":
                    logical_source = str(target)
                    logical_target = str(source)
                else:
                    logical_source = str(source)
                    logical_target = str(target)
                if _canonical_text(logical_source) != _canonical_text(source_filter):
                    continue
                slot = candidate_slots.get(logical_target)
                if slot is None:
                    continue
                rows.append((source_id, relation_id, slot, 1))

    if len(rows) > rows_per_party:
        rows = rows[:rows_per_party]

    rows.extend([(0, 0, 0, 0)] * (rows_per_party - len(rows)))
    return rows


def _candidate_slots(
    parties: list[dict],
    setup_key: str,
    source: str,
    relation: str,
    direction: str,
    capacity: int,
) -> tuple[dict[str, int], list[dict]]:
    candidates: list[str] = []
    seen = set()
    for party in parties:
        graph, _ = _load_party(Path(party["data"]))
        for graph_source, adjacency in graph.items():
            for graph_relation, targets in adjacency.items():
                if _canonical_text(graph_relation) != _canonical_text(relation):
                    continue
                for target in targets:
                    if direction == "reverse":
                        logical_source = str(target)
                        logical_target = str(graph_source)
                    else:
                        logical_source = str(graph_source)
                        logical_target = str(target)
                    if _canonical_text(logical_source) != _canonical_text(source):
                        continue
                    if logical_target in seen:
                        continue
                    seen.add(logical_target)
                    candidates.append(logical_target)

    candidates = candidates[:capacity]
    slots = {candidate: index for index, candidate in enumerate(candidates)}
    public_candidates = [
        {
            "slot": slot,
            "display": candidate,
            "entity_id": _hmac_int(setup_key, "entity", candidate),
        }
        for candidate, slot in slots.items()
    ]
    return slots, public_candidates


def _write_input_file(path: Path, values: list[int]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(str(value) for value in values) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--edge", required=True, type=_parse_edge)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--rows-per-party", type=int, default=256)
    parser.add_argument("--candidate-capacity", type=int, default=64)
    parser.add_argument("--semantic-relations", action="store_true")
    args = parser.parse_args()

    setup_key = os.environ.get("FEDKG_SETUP_KEY")
    if not setup_key:
        raise SystemExit("FEDKG_SETUP_KEY is required")

    source, original_relation, target = args.edge
    relation, direction = _normalize_relation(original_relation, semantic_relations=args.semantic_relations)
    if not _is_unknown(target):
        raise SystemExit("this prototype expects TARGET to be UNKNOWN")

    manifest = _load_manifest(Path(args.manifest))
    parties = manifest["parties"]
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    candidate_slots, public_candidates = _candidate_slots(
        parties=parties,
        setup_key=setup_key,
        source=source,
        relation=relation,
        direction=direction,
        capacity=args.candidate_capacity,
    )

    template_path = _repo_root() / "mpspdz_client_excluded" / "programs" / "secure_kg_lookup_topk.mpc.template"
    program = template_path.read_text().format(
        rows_per_party=args.rows_per_party,
        data_parties=len(parties),
        candidate_capacity=args.candidate_capacity,
    )
    (output_dir / "secure_kg_lookup_topk.mpc").write_text(program)

    player_data = output_dir / "Player-Data"
    query_values = [
        _hmac_int(setup_key, "entity", source),
        _hmac_int(setup_key, "relation", relation),
    ]
    _write_input_file(player_data / "Input-P0-0", query_values)

    party_summaries = []
    for index, party in enumerate(parties, start=1):
        graph, _ = _load_party(Path(party["data"]))
        rows = _party_edges(
            graph=graph,
            setup_key=setup_key,
            source_filter=source,
            relation_filter=relation,
            direction=direction,
            candidate_slots=candidate_slots,
            rows_per_party=args.rows_per_party,
        )
        flat_values = [value for row in rows for value in row]
        _write_input_file(player_data / f"Input-P{index}-0", flat_values)
        party_summaries.append(
            {
                "player": index,
                "party_id": party["party_id"],
                "real_rows": sum(1 for row in rows if row != (0, 0, 0, 0)),
                "padded_rows": args.rows_per_party,
            }
        )

    mapping = {
        "query": {
            "source": source,
            "original_relation": original_relation,
            "relation": relation,
            "direction": direction,
            "semantic_relations": args.semantic_relations,
            "target": target,
            "source_id": query_values[0],
            "relation_id": query_values[1],
        },
        "data_parties": party_summaries,
        "candidate_capacity": args.candidate_capacity,
        "rows_per_party": args.rows_per_party,
        "candidates": public_candidates,
        "security_note": (
            "This is a bounded local MPC instance. Candidate display names are "
            "stored only for debugging and final interpretation, not as MPC inputs."
        ),
    }
    (output_dir / "public_mapping.json").write_text(json.dumps(mapping, indent=2))

    print(json.dumps({"output_dir": str(output_dir), **mapping}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
