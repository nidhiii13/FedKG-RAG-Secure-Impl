"""CLI for the EXPERIMENTAL relation-paged adjacency layout.

Separate from ``prepare_scan`` on purpose: this backend has its own config
format and its own generated program, so it must not be reachable from the
supported preparation path by accident. Run it with
``doram_t2_3pc.run_pages_mpspdz``.
"""

from __future__ import annotations

import argparse
import json

from .io import read_json
from .packed import create_packed_query_batch_shards
from .page_program import write_program
from .paged_shares import (
    assemble_paged_batch_from_paths,
    create_paged_owner_shards,
)
from .relation_pages import (
    check_global_frontier,
    RelationPageConfig,
    build_owner_page_layout,
    evaluate_paged_cleartext,
    owner_layout_report,
    paged_cost_estimate,
    relation_split_cost_advantage,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare, cost, and generate programs for the experimental "
            "relation-paged layout"
        )
    )
    sub = parser.add_subparsers(dest="command", required=True)

    owner_shards = sub.add_parser(
        "owner", help="create one owner's three paged shards"
    )
    owner_shards.add_argument("--config", required=True)
    owner_shards.add_argument("--owner", required=True)
    owner_shards.add_argument("--edges", required=True)
    owner_shards.add_argument("--output-dir", required=True)

    query_batch = sub.add_parser(
        "query-batch",
        help="create the client's three query shards (same contract as the scan backend)",
    )
    query_batch.add_argument("--config", required=True)
    query_batch.add_argument("--queries", required=True)
    query_batch.add_argument("--output-dir", required=True)

    assemble = sub.add_parser(
        "assemble", help="assemble one server's private input"
    )
    assemble.add_argument("--config", required=True)
    assemble.add_argument("--server", required=True, type=int)
    assemble.add_argument("--query-count", required=True, type=int)
    assemble.add_argument("--query-shard", required=True)
    assemble.add_argument("--owner-shard", action="append", required=True)
    assemble.add_argument("--output", required=True)

    program = sub.add_parser(
        "program", help="write the generated MP-SPDZ program without running it"
    )
    program.add_argument("--config", required=True)
    program.add_argument("--query-count", required=True, type=int)
    program.add_argument("--output-dir", required=True)

    audit = sub.add_parser(
        "audit-owner",
        help="build one owner's paged layout and report private occupancy",
    )
    audit.add_argument("--config", required=True)
    audit.add_argument("--owner", required=True)
    audit.add_argument("--edges", required=True)

    gf = sub.add_parser(
        "check-global-frontier",
        help=(
            "verify the federation-wide global_frontier bound (OFFLINE ONLY: "
            "needs the plaintext union, which a real deployment does not have)"
        ),
    )
    gf.add_argument("--config", required=True)
    gf.add_argument(
        "--owner-edges",
        required=True,
        action="append",
        help="owner=path/to/edges.json, repeated once per owner",
    )

    estimate = sub.add_parser(
        "estimate",
        help="print public circuit-shape costs for the paged layout",
    )
    estimate.add_argument("--config", required=True)
    estimate.add_argument("--query-count", required=True, type=int)
    estimate.add_argument(
        "--compacted-frontier-slots",
        type=int,
        help="model composing the layout with oblivious frontier compaction",
    )
    estimate.add_argument(
        "--lossless-fanout-per-owner",
        type=int,
        help=(
            "max source degree of the raw dataset; enables the like-for-like "
            "comparison against a packed scan wide enough to be lossless"
        ),
    )

    oracle = sub.add_parser(
        "evaluate",
        help="run the cleartext paged oracle for one query (testing only)",
    )
    oracle.add_argument("--config", required=True)
    oracle.add_argument("--owner-edges", action="append", required=True,
                        help="owner=path/to/edges.json")
    oracle.add_argument("--query", required=True)

    args = parser.parse_args()
    config = RelationPageConfig.load(args.config)

    if args.command == "owner":
        for path in create_paged_owner_shards(
            config, args.owner, args.edges, args.output_dir
        ):
            print(path)
        return

    if args.command == "query-batch":
        # The query contract is identical to the packed scan backend.
        for path in create_packed_query_batch_shards(
            config.base, args.queries, args.output_dir
        ):
            print(path)
        return

    if args.command == "assemble":
        print(
            assemble_paged_batch_from_paths(
                config,
                args.server,
                args.query_count,
                args.query_shard,
                args.owner_shard,
                args.output,
            )
        )
        return

    if args.command == "program":
        print(write_program(config, args.query_count, args.output_dir))
        return

    if args.command == "audit-owner":
        edges = read_json(args.edges)
        if not isinstance(edges, list):
            raise ValueError("owner edge file must be a JSON list")
        layout = build_owner_page_layout(config, args.owner, edges)
        print(json.dumps(owner_layout_report(layout, config), indent=2, sort_keys=True))
        return

    if args.command == "check-global-frontier":
        owner_edges = {}
        for item in args.owner_edges:
            owner, _, path = item.partition("=")
            if not owner or not path:
                raise ValueError("--owner-edges must be owner=path")
            edges = read_json(path)
            if not isinstance(edges, list):
                raise ValueError(f"owner edge file must be a JSON list: {path}")
            owner_edges[owner] = edges
        print(json.dumps(check_global_frontier(config, owner_edges),
                         indent=2, sort_keys=True))
        return

    if args.command == "estimate":
        report = paged_cost_estimate(
            config,
            args.query_count,
            compacted_frontier_slots=args.compacted_frontier_slots,
        )
        if args.lossless_fanout_per_owner:
            report["lossless_comparison"] = relation_split_cost_advantage(
                config,
                args.lossless_fanout_per_owner,
                args.query_count,
                compacted_frontier_slots=args.compacted_frontier_slots,
            )
        print(json.dumps(report, indent=2, sort_keys=True))
        return

    owner_edges = {}
    for item in args.owner_edges:
        if "=" not in item:
            raise ValueError("--owner-edges expects owner=path")
        owner, path = item.split("=", 1)
        value = read_json(path)
        if not isinstance(value, list):
            raise ValueError(f"owner edge file must be a JSON list: {path}")
        owner_edges[owner] = value
    query = read_json(args.query)
    if isinstance(query, list):
        if len(query) != 1:
            raise ValueError("evaluate accepts exactly one query")
        query = query[0]
    print(
        json.dumps(
            evaluate_paged_cleartext(config, owner_edges, query),
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
