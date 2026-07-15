#!/usr/bin/env python3
"""Export plaintext-free KG index replicas for two FSS evaluators."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.crypto.hmac_ids import HmacIdProvider
from src.party.opaque_index_snapshot import OpaqueIndexSnapshot
from src.party.secure_index import SecurePartyIndex
from src.runtime.opaque_index_replication import replicate_opaque_snapshots, verify_replicas
from src.runtime.secure_roles import SecureRoleTopology
from src.runtime.simgrag_loader import load_manifest, load_party_payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export replicated HMAC-only indexes for the two native FSS evaluators."
    )
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--topology", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--key-env", default="FEDKG_SETUP_KEY")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    topology = SecureRoleTopology.from_json(args.topology)
    manifest = load_manifest(args.manifest)
    manifest_party_ids = [party.party_id for party in manifest.parties]
    topology.validate_contributor_ids(manifest_party_ids)

    ids = HmacIdProvider.from_env(args.key_env)
    snapshots = []
    for party in manifest.parties:
        graph, types = load_party_payload(party.data_path)
        secure_index = SecurePartyIndex.from_plain_graph(party.party_id, graph, types, ids)
        snapshots.append(OpaqueIndexSnapshot.from_secure_index(secure_index, ids))

    replicas = replicate_opaque_snapshots(
        snapshots,
        topology.fss_evaluator_ids,
        args.output_dir,
    )
    verify_replicas(replicas)
    print(
        json.dumps(
            {
                "snapshot_version": snapshots[0].version,
                "partition_count": len(snapshots),
                "fss_evaluator_count": len(replicas),
                "replicas_identical": True,
                "output_dir": str(args.output_dir),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

