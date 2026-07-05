#!/usr/bin/env python3
"""Run a private exact KG query over SimGRAG federated party data.

The intended private mode is `--universe full`, where all parties evaluate DPF
shares over the same opaque HMAC-ID universe. This can be expensive with the
current per-eval CLI process model. `--universe query-ids` is a small smoke mode
for validating the native DPF backend only; it is not private because the
evaluation universe is exactly the queried IDs.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.aggregation.private_lookup import PrivateLookupAggregator
from src.common.types import PrivateEvaluationUniverse, QueryEdge
from src.crypto.fss_cli_backend import FssCliBackend
from src.crypto.hmac_ids import HmacIdProvider
from src.gateway.query_compiler import ExactQueryCompiler
from src.orchestration.encoded_exact_retriever import EncodedExactRetriever
from src.orchestration.private_universe import build_private_evaluation_universe
from src.party.private_evaluator import PrivatePartyEvaluator
from src.party.secure_index import SecurePartyIndex
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


def query_id_universe(query_graph: list[QueryEdge], compiler: ExactQueryCompiler) -> PrivateEvaluationUniverse:
    exact = compiler.compile_ids(query_graph)
    return PrivateEvaluationUniverse(
        node_points={label: [encoded] for label, encoded in exact.node_ids.items()},
        relation_points={label: [encoded] for label, encoded in exact.relation_ids.items()},
        type_points={label: [encoded] for label, encoded in exact.type_ids.items()},
    )


def universe_size(universe: PrivateEvaluationUniverse) -> int:
    return (
        sum(len(points) for points in universe.node_points.values())
        + sum(len(points) for points in universe.relation_points.values())
        + sum(len(points) for points in universe.type_points.values())
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run private exact retrieval over secure HMAC party indexes")
    parser.add_argument("--manifest", required=True, help="Path to SimGRAG federated manifest JSON")
    parser.add_argument("--edge", action="append", type=parse_edge, required=True, help="Query edge as 'source|relation|target'. Repeat for multi-hop queries.")
    parser.add_argument("--fss-cli", default="build/fss_cli/fedkg-fss-cli", help="Path to native FSS CLI executable")
    parser.add_argument("--key-env", default="FEDKG_SETUP_KEY")
    parser.add_argument("--topk", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--universe", choices=["full", "query-ids"], default="full")
    parser.add_argument("--max-universe-size", type=int, default=2000, help="Abort full mode above this many DPF eval points unless --allow-large-universe is set")
    parser.add_argument("--allow-large-universe", action="store_true")
    parser.add_argument("--eval-batch-size", type=int, default=256, help="Maximum points per native eval_many call")
    args = parser.parse_args()

    executable = Path(args.fss_cli)
    if not executable.exists():
        raise SystemExit(f"FSS CLI not found: {executable}. Build it with: cmake --build build/fss_cli")

    ids = HmacIdProvider.from_env(args.key_env)
    parties = load_indexes(args.manifest, ids)
    query_graph = list(args.edge)
    party_ids = [party.party_id for party in parties]

    compiler = ExactQueryCompiler(ids)
    backend = FssCliBackend.from_executable(executable, timeout_seconds=args.timeout, max_eval_batch_size=args.eval_batch_size)
    shares = compiler.compile_private_shares(query_graph, party_ids, backend)

    if args.universe == "full":
        universe = build_private_evaluation_universe(query_graph, parties)
    else:
        universe = query_id_universe(query_graph, compiler)

    size = universe_size(universe)
    if args.universe == "full" and size > args.max_universe_size and not args.allow_large_universe:
        raise SystemExit(
            f"Full private universe has {size} eval points. Current backend starts one process per eval, "
            f"so this may be slow. Re-run with --allow-large-universe or use --universe query-ids for a non-private smoke test."
        )

    eval_shares = [
        PrivatePartyEvaluator(party, backend).evaluate(shares[party.party_id], universe)
        for party in parties
    ]
    candidates = PrivateLookupAggregator(party_ids).aggregate(eval_shares)
    result = EncodedExactRetriever(parties, final_topk=args.topk).retrieve_from_candidates(query_graph, candidates)

    output = {
        "query": query_graph,
        "universe": args.universe,
        "universe_eval_points": size,
        "results": [
            {"score": item.score, "edges": item.edges, "reuse_nodes": item.reuse_nodes}
            for item in result["results"]
        ],
    }
    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
