#!/usr/bin/env python3
"""Generate a synthetic fixture with controlled source-degree skew.

The relation-paged layout narrows a bucket from the maximum *source* degree to
the maximum *(source, relation)* degree. This generator makes that ratio an
explicit knob so the crossover against the packed scan can be measured rather
than argued: every hub source carries ``degree_per_relation`` edges under each
of the ``relations`` relations, so

    max source degree            = relations * degree_per_relation
    max (source, relation) degree = degree_per_relation

and the narrowing factor is exactly ``relations``. The packed scan must set
``fanout_per_owner`` to the former; the paged layout sets ``page_size`` to the
latter.

Both emitted configurations describe the *same* edges, so an A/B run measures
layout cost at identical semantics, and both cleartext oracles must agree.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


SCALABLE_PRIME = 170141183460469231731687303715884105727


def build(args: argparse.Namespace) -> dict[str, Any]:
    entities = [f"e{index}" for index in range(args.entities)]
    relations = [f"r{index}" for index in range(args.relations)]
    owners = [f"owner_{index}" for index in range(args.owners)]

    # Hubs are the high-degree sources. Their targets are drawn from a disjoint
    # tail region so that every first hop lands on a source that also has
    # outgoing edges, guaranteeing non-empty two-hop results.
    hub_count = args.hub_sources
    if hub_count * 2 > args.entities:
        raise SystemExit("need at least 2 * hub_sources entities")
    hubs = entities[:hub_count]
    mids = entities[hub_count : hub_count * 2]
    tails = entities[hub_count * 2 :] or mids

    owner_edges: dict[str, list[dict[str, Any]]] = {owner: [] for owner in owners}
    handle = 1
    for owner_index, owner in enumerate(owners):
        rows = owner_edges[owner]
        for hub_index, hub in enumerate(hubs):
            for relation_index, relation in enumerate(relations):
                for slot in range(args.degree_per_relation):
                    target = mids[(hub_index + slot + relation_index) % len(mids)]
                    rows.append(
                        {
                            "source": hub,
                            "relation": relation,
                            "target": target,
                            "evidence": handle,
                            "score": 1 + (handle % 7),
                        }
                    )
                    handle += 1
        # Mid entities carry the second hop, at the same per-relation degree so
        # the declared bounds hold uniformly.
        for mid_index, mid in enumerate(mids):
            for relation_index, relation in enumerate(relations):
                for slot in range(args.degree_per_relation):
                    target = tails[
                        (mid_index + slot + relation_index + owner_index) % len(tails)
                    ]
                    rows.append(
                        {
                            "source": mid,
                            "relation": relation,
                            "target": target,
                            "evidence": handle,
                            "score": 1 + (handle % 5),
                        }
                    )
                    handle += 1

    max_source_degree = args.relations * args.degree_per_relation
    keys_per_owner = (len(hubs) + len(mids)) * args.relations

    base_config = {
        "owners": owners,
        "entities": {name: index + 1 for index, name in enumerate(entities)},
        "relations": {name: index + 1 for index, name in enumerate(relations)},
        "fanout_per_owner": max_source_degree,
        "top_k": args.top_k,
        "field_prime": SCALABLE_PRIME,
    }
    paged_config = dict(base_config)
    paged_config["relation_page_layout"] = {
        "page_size": args.degree_per_relation,
        "pages_per_key": 1,
        "page_budget": keys_per_owner + 1,
        "frontier_per_owner": args.degree_per_relation,
    }

    queries = [
        {
            "source": hubs[index % len(hubs)],
            "relation_1": relations[index % args.relations],
            "relation_2": relations[(index + 1) % args.relations],
        }
        for index in range(args.query_count)
    ]

    return {
        "owner_edges": owner_edges,
        "scan_config": base_config,
        "paged_config": paged_config,
        "queries": queries,
        "profile": {
            "max_source_degree_per_owner": max_source_degree,
            "max_source_relation_degree_per_owner": args.degree_per_relation,
            "narrowing_factor": args.relations,
            "distinct_source_relation_keys_per_owner": keys_per_owner,
            "edges_per_owner": len(owner_edges[owners[0]]),
            "scan_block_edges": args.owners * max_source_degree,
            "scan_candidates_per_query": (args.owners * max_source_degree) ** 2,
            "paged_second_width": args.owners * args.degree_per_relation,
            "paged_candidates_per_query": (args.owners * args.degree_per_relation) ** 2,
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--entities", type=int, default=100)
    parser.add_argument("--relations", type=int, default=8)
    parser.add_argument("--owners", type=int, default=2)
    parser.add_argument("--hub-sources", type=int, default=8)
    parser.add_argument("--degree-per-relation", type=int, default=2)
    parser.add_argument("--top-k", type=int, default=4)
    parser.add_argument("--query-count", type=int, default=1)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    built = build(args)
    out = args.output_dir
    out.mkdir(parents=True, exist_ok=True)
    for owner, rows in built["owner_edges"].items():
        (out / f"{owner}.json").write_text(json.dumps(rows, indent=1) + "\n")
    (out / "config_scan.json").write_text(
        json.dumps(built["scan_config"], indent=1) + "\n"
    )
    (out / "config_paged.json").write_text(
        json.dumps(built["paged_config"], indent=1) + "\n"
    )
    (out / "queries.json").write_text(json.dumps(built["queries"], indent=1) + "\n")
    (out / "profile.json").write_text(
        json.dumps(built["profile"], indent=1, sort_keys=True) + "\n"
    )
    print(json.dumps(built["profile"], indent=2, sort_keys=True))
    print(f"Wrote fixture to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
