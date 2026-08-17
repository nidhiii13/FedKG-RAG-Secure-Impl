from __future__ import annotations

import argparse
import json

from .capacity_planning import plan_owner_capacity, retention
from .config import PublicConfig
from .io import read_json
from .packed import (
    assemble_packed_batch_from_paths,
    create_packed_owner_shards,
    create_packed_query_batch_shards,
    packed_owner_capacity_report,
)
from .scan_program import scan_cost_estimate


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prepare private inputs for the packed MPC-oblivious scan"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    owner = sub.add_parser("owner")
    owner.add_argument("--config", required=True)
    owner.add_argument("--owner", required=True)
    owner.add_argument("--edges", required=True)
    owner.add_argument("--output-dir", required=True)

    audit_owner = sub.add_parser(
        "audit-owner",
        help="report private owner-local capacity requirements without sharing data",
    )
    audit_owner.add_argument("--config", required=True)
    audit_owner.add_argument("--owner", required=True)
    audit_owner.add_argument("--edges", required=True)

    plan = sub.add_parser(
        "plan-capacity",
        help=(
            "profile a RAW, unbounded owner edge file and report the capacity "
            "each layout would need; never enforces the configured bounds"
        ),
    )
    plan.add_argument("--edges", required=True)
    plan.add_argument(
        "--bounded-edges",
        help="optional already-capped file to measure retained-edge fraction",
    )
    plan.add_argument(
        "--page-sizes",
        default="1,2,4,8,16,32,64",
        help="comma-separated candidate relation-page sizes",
    )
    plan.add_argument("--pages-per-key", type=int, default=1)

    estimate = sub.add_parser(
        "estimate",
        help="print public circuit-shape costs for the configured scan backend",
    )
    estimate.add_argument("--config", required=True)
    estimate.add_argument("--query-count", required=True, type=int)

    query = sub.add_parser("query-batch")
    query.add_argument("--config", required=True)
    query.add_argument("--queries", required=True)
    query.add_argument("--output-dir", required=True)

    assemble = sub.add_parser("assemble")
    assemble.add_argument("--config", required=True)
    assemble.add_argument("--server", required=True, type=int)
    assemble.add_argument("--query-count", required=True, type=int)
    assemble.add_argument("--query-shard", required=True)
    assemble.add_argument("--owner-shard", action="append", required=True)
    assemble.add_argument("--output", required=True)

    args = parser.parse_args()
    if args.command == "plan-capacity":
        # Deliberately config-free: a raw dataset is profiled precisely when it
        # may not fit any bounds that a public configuration could declare.
        edges = read_json(args.edges)
        if not isinstance(edges, list):
            raise ValueError("owner edge file must be a JSON list")
        report = plan_owner_capacity(
            edges,
            candidate_page_sizes=[
                int(value) for value in args.page_sizes.split(",") if value
            ],
            pages_per_key=args.pages_per_key,
        )
        if args.bounded_edges:
            bounded = read_json(args.bounded_edges)
            if not isinstance(bounded, list):
                raise ValueError("bounded edge file must be a JSON list")
            report["retention_vs_bounded_file"] = retention(edges, bounded)
        print(json.dumps(report, indent=2, sort_keys=True))
        return

    config = PublicConfig.load(args.config)
    if args.command == "owner":
        create_packed_owner_shards(
            config, args.owner, args.edges, args.output_dir
        )
    elif args.command == "audit-owner":
        edges = read_json(args.edges)
        if not isinstance(edges, list) or any(
            not isinstance(edge, dict) for edge in edges
        ):
            raise ValueError("owner edge file must be a JSON list of objects")
        print(
            json.dumps(
                packed_owner_capacity_report(config, args.owner, edges),
                indent=2,
                sort_keys=True,
            )
        )
    elif args.command == "estimate":
        print(
            json.dumps(
                scan_cost_estimate(config, args.query_count),
                indent=2,
                sort_keys=True,
            )
        )
    elif args.command == "query-batch":
        create_packed_query_batch_shards(config, args.queries, args.output_dir)
    else:
        assemble_packed_batch_from_paths(
            config,
            args.server,
            args.query_count,
            args.query_shard,
            args.owner_shard,
            args.output,
        )


if __name__ == "__main__":
    main()
