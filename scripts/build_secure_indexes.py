#!/usr/bin/env python3
"""Build party-local HMAC indexes from a SimGRAG federated manifest."""

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.crypto.hmac_ids import HmacIdProvider
from src.party.secure_index import SecurePartyIndex
from src.runtime.simgrag_loader import load_manifest, load_party_payload


def main():
    parser = argparse.ArgumentParser(description="Build HMAC encoded party indexes from SimGRAG party data")
    parser.add_argument("--manifest", required=True, help="Path to ../SimGRAG/configs/federated/*_manifest.json")
    parser.add_argument("--output", required=True, help="Output JSON summary path")
    parser.add_argument("--key-env", default="FEDKG_SETUP_KEY")
    args = parser.parse_args()

    ids = HmacIdProvider.from_env(args.key_env)
    manifest = load_manifest(args.manifest)
    summary = {"dataset": manifest.dataset, "party_count": len(manifest.parties), "party_summaries": []}
    for spec in manifest.parties:
        graph, types = load_party_payload(spec.data_path)
        index = SecurePartyIndex.from_plain_graph(spec.party_id, graph, types, ids)
        summary["party_summaries"].append(
            {
                "nodes": len(index.adjacency),
                "relations": len(index.local_relations),
                "types": len(index.type_index),
            }
        )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
