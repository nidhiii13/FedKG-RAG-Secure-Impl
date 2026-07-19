#!/usr/bin/env python3
"""Prepare a bounded two-hop MetaQA instance for MP-SPDZ.

This script precomputes bounded two-hop path rows per data party and lets
MP-SPDZ privately match those rows against secret query inputs. It is a next
step toward N-party, client-excluded private retrieval, not a full private graph
database.
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
RELATION_ALIASES = {
    "act in": "starred_actors",
    "acted in": "starred_actors",
    "acting in": "starred_actors",
    "actor of": "starred_actors",
    "appear in": "starred_actors",
    "appeared in": "starred_actors",
    "appears in": "starred_actors",
    "cast in": "starred_actors",
    "star in": "starred_actors",
    "starred in": "starred_actors",
    "stars in": "starred_actors",
    "acted by": "starred_actors",
    "is acted by": "starred_actors",
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


def _hmac_int(setup_key: str, namespace: str, value: str) -> int:
    message = f"{namespace}:{_canonical_text(value)}".encode("utf-8")
    digest = hmac.new(setup_key.encode("utf-8"), message, hashlib.sha256).digest()
    return int.from_bytes(digest[:8], "big") & FIELD_MASK


def _path_id(setup_key: str, source: str, relation_1: str, mid: str, relation_2: str, target: str) -> int:
    value = json.dumps(
        [
            _canonical_text(source),
            _canonical_text(relation_1),
            _canonical_text(mid),
            _canonical_text(relation_2),
            _canonical_text(target),
        ],
        separators=(",", ":"),
    )
    return _hmac_int(setup_key, "path", value)


def _parse_edge(value: str) -> tuple[str, str, str]:
    parts = [part.strip() for part in value.split("|")]
    if len(parts) != 3:
        raise argparse.ArgumentTypeError("edge must be SOURCE|RELATION|TARGET")
    return parts[0], parts[1], parts[2]


def _normalize_relation(relation: str, *, semantic_relations: bool) -> str:
    if not semantic_relations:
        return relation
    return RELATION_ALIASES.get(_canonical_text(relation), relation)


def _normalize_edge_relations(
    edge: tuple[str, str, str], *, semantic_relations: bool
) -> tuple[str, str, str]:
    source, relation, target = edge
    return source, _normalize_relation(relation, semantic_relations=semantic_relations), target


def _load_manifest(path: Path) -> dict:
    with path.open() as handle:
        return json.load(handle)


def _targets(graph: dict, source: str, relation: str) -> list[str]:
    adjacency = graph.get(source, {})
    return [str(target) for target in adjacency.get(relation, [])]


def _candidate_paths(
    parties: list[dict],
    setup_key: str,
    edge_1: tuple[str, str, str],
    edge_2: tuple[str, str, str],
    capacity: int,
) -> tuple[dict[tuple[str, str, str], int], list[dict]]:
    source_1, relation_1, mid_1 = edge_1
    mid_2, relation_2, target_2 = edge_2
    if not _is_unknown(mid_1) or not _is_unknown(mid_2):
        raise SystemExit("two-hop prototype expects UNKNOWN as the connecting middle node")

    paths: list[tuple[str, str, str]] = []
    seen = set()
    target_is_unknown = _is_unknown(target_2)

    for party in parties:
        graph, _ = _load_party(Path(party["data"]))
        for mid in _targets(graph, source_1, relation_1):
            for target in _targets(graph, mid, relation_2):
                if not target_is_unknown and _canonical_text(target) != _canonical_text(target_2):
                    continue
                key = (source_1, mid, target)
                if key in seen:
                    continue
                seen.add(key)
                paths.append(key)

    paths = paths[:capacity]
    slots = {path: index for index, path in enumerate(paths)}
    public_paths = [
        {
            "slot": slot,
            "source": source,
            "relation_1": relation_1,
            "middle": mid,
            "relation_2": relation_2,
            "target": target,
            "path_id": _path_id(setup_key, source, relation_1, mid, relation_2, target),
            "source_id": _hmac_int(setup_key, "entity", source),
            "middle_id": _hmac_int(setup_key, "entity", mid),
            "target_id": _hmac_int(setup_key, "entity", target),
        }
        for (source, mid, target), slot in slots.items()
    ]
    return slots, public_paths


def _party_path_rows(
    graph: dict,
    setup_key: str,
    edge_1: tuple[str, str, str],
    edge_2: tuple[str, str, str],
    path_slots: dict[tuple[str, str, str], int],
    rows_per_party: int,
) -> list[tuple[int, int, int, int, int, int]]:
    source_1, relation_1, _ = edge_1
    _, relation_2, target_2 = edge_2
    target_is_unknown = _is_unknown(target_2)
    rows: list[tuple[int, int, int, int, int, int]] = []

    source_id = _hmac_int(setup_key, "entity", source_1)
    relation_1_id = _hmac_int(setup_key, "relation", relation_1)
    relation_2_id = _hmac_int(setup_key, "relation", relation_2)

    for mid in _targets(graph, source_1, relation_1):
        for target in _targets(graph, mid, relation_2):
            if not target_is_unknown and _canonical_text(target) != _canonical_text(target_2):
                continue
            slot = path_slots.get((source_1, mid, target))
            if slot is None:
                continue
            target_id = _hmac_int(setup_key, "entity", target)
            rows.append((source_id, relation_1_id, relation_2_id, target_id, slot, 1))

    if len(rows) > rows_per_party:
        rows = rows[:rows_per_party]

    rows.extend([(0, 0, 0, 0, 0, 0)] * (rows_per_party - len(rows)))
    return rows


def _write_input_file(path: Path, values: list[int]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(str(value) for value in values) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--edge", required=True, action="append", type=_parse_edge)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--rows-per-party", type=int, default=256)
    parser.add_argument("--path-capacity", type=int, default=64)
    parser.add_argument("--reveal-mode", choices=("all_scores", "topk"), default="all_scores")
    parser.add_argument("--topk", type=int, default=3)
    parser.add_argument(
        "--semantic-relations",
        action="store_true",
        help="Map common natural-language MetaQA relation phrases to canonical KG relations before MPC encoding.",
    )
    args = parser.parse_args()

    if len(args.edge) != 2:
        raise SystemExit("two-hop prototype requires exactly two --edge values")

    setup_key = os.environ.get("FEDKG_SETUP_KEY")
    if not setup_key:
        raise SystemExit("FEDKG_SETUP_KEY is required")

    original_edge_1, original_edge_2 = args.edge
    edge_1 = _normalize_edge_relations(original_edge_1, semantic_relations=args.semantic_relations)
    edge_2 = _normalize_edge_relations(original_edge_2, semantic_relations=args.semantic_relations)
    target = edge_2[2]
    target_is_unknown = 1 if _is_unknown(target) else 0
    target_id = 0 if target_is_unknown else _hmac_int(setup_key, "entity", target)

    manifest = _load_manifest(Path(args.manifest))
    parties = manifest["parties"]
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    path_slots, public_paths = _candidate_paths(
        parties=parties,
        setup_key=setup_key,
        edge_1=edge_1,
        edge_2=edge_2,
        capacity=args.path_capacity,
    )

    if args.reveal_mode == "topk":
        if args.topk < 1:
            raise SystemExit("--topk must be positive")
        template_name = "secure_kg_twohop_private_topk.mpc.template"
        program_name = "secure_kg_twohop_private_topk.mpc"
        program_args = {
            "rows_per_party": args.rows_per_party,
            "data_parties": len(parties),
            "path_capacity": args.path_capacity,
            "top_k": min(args.topk, args.path_capacity),
            "max_score": args.rows_per_party * len(parties) + 1,
        }
    else:
        template_name = "secure_kg_twohop_lookup_topk.mpc.template"
        program_name = "secure_kg_twohop_lookup_topk.mpc"
        program_args = {
            "rows_per_party": args.rows_per_party,
            "data_parties": len(parties),
            "path_capacity": args.path_capacity,
        }

    template_path = _repo_root() / "mpspdz_client_excluded" / "programs" / template_name
    program = template_path.read_text().format(**program_args)
    (output_dir / program_name).write_text(program)

    player_data = output_dir / "Player-Data"
    query_values = [
        _hmac_int(setup_key, "entity", edge_1[0]),
        _hmac_int(setup_key, "relation", edge_1[1]),
        _hmac_int(setup_key, "relation", edge_2[1]),
        target_id,
        target_is_unknown,
    ]
    _write_input_file(player_data / "Input-P0-0", query_values)

    party_summaries = []
    for index, party in enumerate(parties, start=1):
        graph, _ = _load_party(Path(party["data"]))
        rows = _party_path_rows(
            graph=graph,
            setup_key=setup_key,
            edge_1=edge_1,
            edge_2=edge_2,
            path_slots=path_slots,
            rows_per_party=args.rows_per_party,
        )
        flat_values = [value for row in rows for value in row]
        _write_input_file(player_data / f"Input-P{index}-0", flat_values)
        party_summaries.append(
            {
                "player": index,
                "party_id": party["party_id"],
                "real_rows": sum(1 for row in rows if row != (0, 0, 0, 0, 0, 0)),
                "padded_rows": args.rows_per_party,
            }
        )

    mapping = {
        "query": {
            "original_edges": [
                {"source": original_edge_1[0], "relation": original_edge_1[1], "target": original_edge_1[2]},
                {"source": original_edge_2[0], "relation": original_edge_2[1], "target": original_edge_2[2]},
            ],
            "edges": [
                {"source": edge_1[0], "relation": edge_1[1], "target": edge_1[2]},
                {"source": edge_2[0], "relation": edge_2[1], "target": edge_2[2]},
            ],
            "semantic_relations": args.semantic_relations,
            "source_id": query_values[0],
            "relation_1_id": query_values[1],
            "relation_2_id": query_values[2],
            "target_id": target_id,
            "target_is_unknown": target_is_unknown,
        },
        "data_parties": party_summaries,
        "path_capacity": args.path_capacity,
        "rows_per_party": args.rows_per_party,
        "reveal_mode": args.reveal_mode,
        "topk": args.topk if args.reveal_mode == "topk" else None,
        "paths": public_paths,
        "security_note": (
            "This is a bounded local MPC instance. Path display names are stored "
            "only for debugging and final interpretation, not as MPC inputs."
        ),
    }
    (output_dir / "public_mapping.json").write_text(json.dumps(mapping, indent=2))

    print(json.dumps({"output_dir": str(output_dir), **mapping}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
