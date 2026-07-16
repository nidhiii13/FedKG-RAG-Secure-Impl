#!/usr/bin/env python3
"""Run projected FSS routing, encoded traversal, and local Prio3 validation."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.aggregation.prio3_backend import Prio3LocalBackend
from src.aggregation.prio3_candidates import (
    CandidateVectorConfig,
    PrioCandidateAggregator,
    SessionCandidateHandleProvider,
)
from src.crypto.fss_cli_backend import FssCliBackend
from src.crypto.hmac_ids import HmacIdProvider
from src.orchestration.prio_candidate_pipeline import LocalPrioCandidatePipeline
from src.orchestration.role_separated_encoded_matcher import RoleSeparatedEncodedGraphMatcher
from src.orchestration.role_separated_fss_query import RoleSeparatedFssQueryOrchestrator
from src.orchestration.role_separated_semantic_routing import RoleSeparatedSemanticRouter
from src.runtime.fss_evaluator_service import FssEvaluatorService, FssEvaluatorStore
from src.runtime.fss_projection_builder import OpaqueIndexProjectionBuilder
from src.semantic.simgrag_embeddings import embedder_from_config


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Locally validate semantic FSS routing, encoded traversal, and Prio3 aggregation."
    )
    parser.add_argument("--store-0", required=True, type=Path)
    parser.add_argument("--store-1", required=True, type=Path)
    parser.add_argument(
        "--edge",
        action="append",
        required=True,
        help="Query edge formatted as source|relation|target; repeat for multiple hops.",
    )
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--query-nonce", required=True)
    parser.add_argument("--topk", type=int, default=3)
    parser.add_argument("--relation-capacity", type=int, default=128)
    parser.add_argument("--entity-capacity", type=int, default=65536)
    parser.add_argument("--candidate-capacity", type=int, default=256)
    parser.add_argument("--prio-aggregators", type=int, default=3)
    parser.add_argument(
        "--semantic-bucket-mode",
        choices=("alias", "lsh", "hybrid"),
        default="hybrid",
    )
    parser.add_argument(
        "--embedding-backend",
        choices=("hashing", "simgrag"),
        default="hashing",
    )
    parser.add_argument("--embedding-config", type=Path)
    parser.add_argument("--embedding-model-path", type=Path)
    parser.add_argument("--embedding-device")
    parser.add_argument("--key-env", default="FEDKG_SETUP_KEY")
    parser.add_argument("--handle-key-env", default="FEDKG_PRIO_HANDLE_KEY")
    parser.add_argument(
        "--fss-cli",
        type=Path,
        default=Path("build/fss_cli/fedkg-fss-cli"),
    )
    parser.add_argument(
        "--prio-cli",
        type=Path,
        default=Path("tools/prio3_cli/target/release/fedkg-prio3-cli"),
    )
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--eval-batch-size", type=int, default=256)
    parser.add_argument(
        "--allow-local-reconstruction",
        action="store_true",
        help="Acknowledge local FSS candidate and Prio aggregate reconstruction.",
    )
    return parser.parse_args()


def parse_edges(values: list[str]) -> list[tuple[str, str, str]]:
    edges = []
    for value in values:
        parts = tuple(part.strip() for part in value.split("|"))
        if len(parts) != 3 or any(not part for part in parts):
            raise SystemExit(f"invalid --edge value: {value!r}")
        edges.append(parts)
    return edges  # type: ignore[return-value]


def main() -> int:
    args = parse_args()
    if not args.allow_local_reconstruction:
        raise SystemExit("--allow-local-reconstruction is required for this validation command")
    handle_key_text = os.environ.get(args.handle_key_env)
    if handle_key_text is None:
        raise SystemExit(f"{args.handle_key_env} must be set")
    handle_key = handle_key_text.encode("utf-8")
    nonce = args.query_nonce.encode("utf-8")

    stores = [FssEvaluatorStore.load(path) for path in (args.store_0, args.store_1)]
    if {store.evaluator_index for store in stores} != {0, 1}:
        raise SystemExit("the evaluator stores must have indices 0 and 1")
    fss = FssCliBackend.from_executable(
        args.fss_cli,
        timeout_seconds=args.timeout,
        max_eval_batch_size=args.eval_batch_size,
    )
    services = [FssEvaluatorService(store, fss) for store in stores]
    ids = HmacIdProvider.from_env(args.key_env)
    projection_builder = OpaqueIndexProjectionBuilder(
        stores[0].index,
        SessionCandidateHandleProvider(handle_key, nonce),
    )
    lookup = RoleSeparatedFssQueryOrchestrator(fss, services, projection_builder)
    semantic_embedder = None
    if args.embedding_backend == "simgrag":
        if args.embedding_config is None:
            raise SystemExit("--embedding-config is required for --embedding-backend simgrag")
        semantic_embedder = embedder_from_config(
            args.embedding_config,
            model_path=args.embedding_model_path,
            device=args.embedding_device,
        )
    semantic = RoleSeparatedSemanticRouter(
        ids,
        lookup,
        bucket_mode=args.semantic_bucket_mode,
        embedder=semantic_embedder,
    )
    matched = RoleSeparatedEncodedGraphMatcher(
        ids,
        lookup,
        stores[0].index,
        semantic_router=semantic,
        relation_capacity=args.relation_capacity,
        entity_capacity=args.entity_capacity,
    ).match(parse_edges(args.edge))

    if len(matched.candidates) > args.candidate_capacity:
        raise SystemExit(
            f"candidate count {len(matched.candidates)} exceeds --candidate-capacity "
            f"{args.candidate_capacity}"
        )
    prio = PrioCandidateAggregator(
        Prio3LocalBackend.from_executable(args.prio_cli, timeout_seconds=args.timeout),
        CandidateVectorConfig(
            aggregator_count=args.prio_aggregators,
            capacity=args.candidate_capacity,
        ),
        SessionCandidateHandleProvider(handle_key, nonce),
    )
    ranked = LocalPrioCandidatePipeline(prio).run(
        matched.party_ids,
        matched.contributions,
        k=args.topk,
    )
    paths_by_id = {candidate.candidate_id: candidate for candidate in matched.candidates}
    print(
        json.dumps(
            {
                "request_id": args.request_id,
                "query": parse_edges(args.edge),
                "selected_candidate_ids": ranked.selected_candidate_ids,
                "selected_encoded_paths": [
                    {
                        "candidate_id": candidate_id,
                        "score": paths_by_id[candidate_id].score,
                        "edges": paths_by_id[candidate_id].edges,
                    }
                    for candidate_id in ranked.selected_candidate_ids
                ],
                "candidate_count": len(matched.candidates),
                "contribution_count": len(matched.contributions),
                "opaque_partition_count": len(matched.party_ids),
                "fss_evaluator_count": 2,
                "prio_aggregator_count": ranked.aggregation.aggregator_count,
                "semantic_bucket_mode": args.semantic_bucket_mode,
                "embedding_backend": args.embedding_backend,
                "local_role_separated_simulation": True,
                "local_reconstruction": True,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
