#!/usr/bin/env python3
"""Prepare a deterministic cross-owner two-hop KG-ORAM correctness fixture."""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from doram_t2_3pc.config import HE_SCALABLE_FIELD_PRIME, PublicConfig
from doram_t2_3pc.io import write_private_lines
from doram_t2_3pc.kg_oram import build_owner_kg_oram
from doram_t2_3pc.kg_oram_program import common_shape, program_name, write_program
from doram_t2_3pc.kg_oram_shares import assemble_server_input, create_owner_shards, create_query_shards
from doram_t2_3pc.oram_epoch import KgOramEpochAuthorization
from doram_t2_3pc.relation_pages import RelationPageConfig, RelationPageParameters


def fixture() -> tuple[RelationPageConfig, dict[str, list[dict[str, object]]], list[dict[str, str]]]:
    config = RelationPageConfig(
        base=PublicConfig.from_dict({
            "owners": ["owner_a", "owner_b"],
            "entities": {"alice": 1, "bob": 2, "carol": 3},
            "relations": {"knows": 1, "likes": 2},
            "fanout_per_owner": 2,
            "top_k": 1,
            "field_prime": HE_SCALABLE_FIELD_PRIME,
        }),
        pages=RelationPageParameters(
            page_size=2,
            pages_per_key=1,
            page_budget=8,
            global_frontier=2,
        ),
    )
    edges = {
        "owner_a": [
            {"source": "alice", "relation": "knows", "target": "bob", "evidence": 11, "score": 4},
            {"source": "alice", "relation": "knows", "target": "carol", "evidence": 12, "score": 3},
        ],
        "owner_b": [
            {"source": "bob", "relation": "likes", "target": "carol", "evidence": 13, "score": 2},
        ],
    }
    queries = [{"source": "alice", "relation_1": "knows", "relation_2": "likes"}]
    return config, edges, queries


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    config, edges, queries = fixture()
    public_config = {
        "owners": list(config.base.owners),
        "entities": config.base.entities,
        "relations": config.base.relations,
        "fanout_per_owner": config.base.fanout_per_owner,
        "top_k": config.base.top_k,
        "field_prime": config.base.field_prime,
        "relation_page_layout": {
            "page_size": config.pages.page_size,
            "pages_per_key": config.pages.pages_per_key,
            "page_budget": config.pages.page_budget,
            "global_frontier": config.pages.global_frontier,
        },
    }
    (args.output_dir / "config.json").write_text(
        json.dumps(public_config, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "queries.json").write_text(
        json.dumps(queries, indent=2) + "\n", encoding="utf-8"
    )
    for owner, owner_edges in edges.items():
        (args.output_dir / f"{owner}.json").write_text(
            json.dumps(owner_edges, indent=2) + "\n", encoding="utf-8"
        )
    owners = [
        build_owner_kg_oram(
            config, owner, edges[owner], chi=4, base_threshold=4,
            rng=random.Random(100 + index),
        )
        for index, owner in enumerate(config.base.owners)
    ]
    shape = common_shape(config, owners, 1)
    epoch = "1" * 64
    owner_shards = [
        create_owner_shards(config, owner, index, query_count=1, epoch_id=epoch)
        for index, owner in enumerate(owners)
    ]
    query_shards = create_query_shards(config, queries, epoch_id=epoch)
    authorization = KgOramEpochAuthorization.accepted(
        config, epoch_id=epoch, query_count=1, bound_violations=0
    )
    for server in range(3):
        _, values = assemble_server_input(
            config, server, [shards[server] for shards in owner_shards], query_shards[server], authorization
        )
        write_private_lines(args.output_dir / f"Input-P{server}-0", values)
    name = program_name(config, shape, 1)
    source = write_program(config, shape, 1, args.output_dir / f"{name}.mpc")
    (args.output_dir / "manifest.json").write_text(json.dumps({
        "program": name,
        "source": str(source),
        "field_prime": config.base.field_prime,
        "field_bits": config.base.field_usable_bits,
        "epoch_id": epoch,
        "expected": [{"valid": 1, "left_evidence": 11, "right_evidence": 13, "score": 6}],
    }, indent=2) + "\n", encoding="utf-8")
    print(name)


if __name__ == "__main__":
    main()
