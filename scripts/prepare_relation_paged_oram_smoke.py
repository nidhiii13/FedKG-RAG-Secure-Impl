#!/usr/bin/env python3
"""Create a deterministic, non-trivial dual-ORAM smoke instance."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from doram_t2_3pc.config import HE_SCALABLE_FIELD_PRIME
from scripts.prepare_relation_paged_oram_instance import prepare_instance


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    config = {
        "owners": ["owner_a", "owner_b"],
        "entities": {"alice": 1, "bob": 2, "carol": 3, "dave": 4},
        "relations": {"knows": 1, "likes": 2},
        "fanout_per_owner": 4,
        "top_k": 2,
        "field_prime": HE_SCALABLE_FIELD_PRIME,
        "relation_page_layout": {
            "page_size": 2,
            "pages_per_key": 2,
            "page_budget": 12,
            "global_frontier": 3,
        },
    }
    queries = [
        {"source": "alice", "relation_1": "knows", "relation_2": "likes"}
    ]
    owners = {
        "owner_a": [
            {"source": "alice", "relation": "knows", "target": "bob", "evidence": 11, "score": 4},
            {"source": "alice", "relation": "knows", "target": "carol", "evidence": 12, "score": 3},
            {"source": "alice", "relation": "knows", "target": "dave", "evidence": 13, "score": 2},
        ],
        "owner_b": [
            {"source": "bob", "relation": "likes", "target": "dave", "evidence": 21, "score": 5},
            {"source": "carol", "relation": "likes", "target": "bob", "evidence": 22, "score": 7},
            {"source": "dave", "relation": "likes", "target": "carol", "evidence": 23, "score": 1},
        ],
    }
    config_path, query_path = output / "config.json", output / "queries.json"
    _write(config_path, config)
    _write(query_path, queries)
    owner_paths: dict[str, Path] = {}
    for owner, edges in owners.items():
        path = output / f"{owner}.json"
        _write(path, edges)
        owner_paths[owner] = path
    manifest = prepare_instance(
        config_path,
        query_path,
        owner_paths,
        output,
        chi=4,
        base_threshold=4,
        statistical_security_bits=80,
        epoch_id="7" * 64,
    )
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
