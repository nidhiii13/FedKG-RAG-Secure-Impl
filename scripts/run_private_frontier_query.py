#!/usr/bin/env python3
"""Run exact chain-shaped private frontier retrieval over SimGRAG party data."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.aggregation.score_aggregation import MatchScoreShareBuilder
from src.common.types import QueryEdge
from src.crypto.fss_cli_backend import FssCliBackend
from src.crypto.hmac_ids import HmacIdProvider
from src.orchestration.cross_party_frontier_matcher import CrossPartyFrontierMatcher
from src.party.secure_index import SecurePartyIndex
from src.ranking.garbled_circuit import LocalGarbledCircuitTopK
from src.runtime.simgrag_loader import load_manifest, load_party_payload


def parse_edge(value: str) -> QueryEdge:
    parts = [part.strip() for part in value.split("|")]
    if len(parts) != 3 or any(not part for part in parts):
        raise argparse.ArgumentTypeError("edge must be formatted as 'source|relation|target'")
    return parts[0], parts[1], parts[2]


def load_indexes(manifest_path: str, ids: HmacIdProvider) -> list[SecurePartyIndex]:
    manifest = load_manifest(manifest_path)
    indexes = []
    for spec in manifest.parties:
        graph, types = load_party_payload(spec.data_path)
        indexes.append(SecurePartyIndex.from_plain_graph(spec.party_id, graph, types, ids))
    return indexes


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run secure exact chain retrieval with DPF/FSS frontier handoff"
    )
    parser.add_argument("--manifest", required=True, help="Path to SimGRAG federated manifest JSON")
    parser.add_argument(
        "--edge",
        action="append",
        type=parse_edge,
        required=True,
        help="Query edge as 'source|relation|target'. Repeat in chain order.",
    )
    parser.add_argument("--fss-cli", default="build/fss_cli/fedkg-fss-cli")
    parser.add_argument("--key-env", default="FEDKG_SETUP_KEY")
    parser.add_argument("--topk", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--eval-batch-size", type=int, default=256)
    parser.add_argument(
        "--semantic-relations",
        action="store_true",
        help="Use private semantic bucket routing for relation labels before exact path expansion",
    )
    parser.add_argument(
        "--semantic-entities",
        action="store_true",
        help="Use private semantic bucket routing for known entity labels before exact path expansion",
    )
    parser.add_argument(
        "--semantic-bucket-mode",
        choices=["alias", "lsh", "hybrid"],
        default="hybrid",
        help="Semantic relation bucket family used by private routing",
    )
    parser.add_argument(
        "--semantic-relation-penalty",
        type=float,
        default=0.25,
        help="Score penalty added for each alias/lexical semantic relation match instead of exact HMAC",
    )
    parser.add_argument(
        "--semantic-lsh-relation-penalty",
        type=float,
        default=0.5,
        help="Score penalty added for each LSH semantic relation match instead of exact HMAC",
    )
    parser.add_argument(
        "--semantic-entity-penalty",
        type=float,
        default=0.2,
        help="Score penalty added for each alias/lexical semantic entity match instead of exact HMAC",
    )
    parser.add_argument(
        "--semantic-lsh-entity-penalty",
        type=float,
        default=0.45,
        help="Score penalty added for each LSH semantic entity match instead of exact HMAC",
    )
    args = parser.parse_args()

    executable = Path(args.fss_cli)
    if not executable.exists():
        raise SystemExit(f"FSS CLI not found: {executable}. Build it with: cmake --build build/fss_cli")

    ids = HmacIdProvider.from_env(args.key_env)
    parties = load_indexes(args.manifest, ids)
    query_graph = list(args.edge)
    backend = FssCliBackend.from_executable(
        executable,
        timeout_seconds=args.timeout,
        max_eval_batch_size=args.eval_batch_size,
    )
    share_count = max(2, len(parties))
    matcher = CrossPartyFrontierMatcher(
        parties=parties,
        ids=ids,
        backend=backend,
        share_builder=MatchScoreShareBuilder(share_count=share_count),
        enable_semantic_relations=args.semantic_relations,
        enable_semantic_entities=args.semantic_entities,
        semantic_bucket_mode=args.semantic_bucket_mode,
        semantic_relation_penalty=args.semantic_relation_penalty,
        semantic_lsh_relation_penalty=args.semantic_lsh_relation_penalty,
        semantic_entity_penalty=args.semantic_entity_penalty,
        semantic_lsh_entity_penalty=args.semantic_lsh_entity_penalty,
    )
    ranked = matcher.retrieve_ranked(
        query_graph,
        LocalGarbledCircuitTopK(party_count=share_count),
        k=args.topk,
    )

    output = {
        "query": query_graph,
        "party_count": len(parties),
        "semantic_relations": args.semantic_relations,
        "semantic_entities": args.semantic_entities,
        "semantic_bucket_mode": args.semantic_bucket_mode if args.semantic_relations or args.semantic_entities else None,
        "selected_candidate_ids": ranked.selected_ids,
        "results": [
            {"score": item.score, "edges": item.edges, "reuse_nodes": item.reuse_nodes}
            for item in ranked.evidence
        ],
        "aggregated_candidate_count": len(ranked.aggregated_shares),
    }
    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
