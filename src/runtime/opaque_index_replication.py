"""Replicate opaque index snapshots to exactly two FSS evaluator stores."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from src.party.opaque_index_snapshot import OpaqueIndexSnapshot


@dataclass(frozen=True)
class ReplicatedSnapshotRecord:
    partition_id: str
    digest: str
    relative_path: str


@dataclass(frozen=True)
class EvaluatorSnapshotManifest:
    evaluator_id: str
    evaluator_index: int
    snapshots: tuple[ReplicatedSnapshotRecord, ...]
    version: str = "fedkg-fss-replica-manifest-v1"

    def as_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "evaluator_id": self.evaluator_id,
            "evaluator_index": self.evaluator_index,
            "snapshots": [
                {
                    "partition_id": record.partition_id,
                    "digest": record.digest,
                    "relative_path": record.relative_path,
                }
                for record in self.snapshots
            ],
        }


def replicate_opaque_snapshots(
    snapshots: Sequence[OpaqueIndexSnapshot],
    evaluator_ids: Sequence[str],
    output_root: str | Path,
) -> Mapping[str, EvaluatorSnapshotManifest]:
    if len(evaluator_ids) != 2 or len(set(evaluator_ids)) != 2:
        raise ValueError("opaque FSS replication requires exactly two unique evaluator IDs")
    if not snapshots:
        raise ValueError("at least one opaque snapshot is required")
    partition_ids = [snapshot.partition_id for snapshot in snapshots]
    if len(partition_ids) != len(set(partition_ids)):
        raise ValueError("opaque snapshot partition IDs must be unique")

    root = Path(output_root)
    manifests = {}
    ordered_snapshots = sorted(snapshots, key=lambda snapshot: snapshot.partition_id)
    for evaluator_index, evaluator_id in enumerate(evaluator_ids):
        evaluator_root = root / evaluator_id
        records = []
        for snapshot in ordered_snapshots:
            relative_path = f"partitions/{snapshot.partition_id}.json"
            snapshot.write(evaluator_root / relative_path)
            records.append(
                ReplicatedSnapshotRecord(
                    partition_id=snapshot.partition_id,
                    digest=snapshot.digest(),
                    relative_path=relative_path,
                )
            )
        manifest = EvaluatorSnapshotManifest(evaluator_id, evaluator_index, tuple(records))
        evaluator_root.mkdir(parents=True, exist_ok=True)
        (evaluator_root / "manifest.json").write_text(
            json.dumps(manifest.as_dict(), indent=2, sort_keys=True)
        )
        manifests[evaluator_id] = manifest
    return manifests


def verify_replicas(manifests: Mapping[str, EvaluatorSnapshotManifest]) -> None:
    if len(manifests) != 2:
        raise ValueError("exactly two evaluator manifests are required")
    record_sets = [
        {(record.partition_id, record.digest) for record in manifest.snapshots}
        for manifest in manifests.values()
    ]
    if record_sets[0] != record_sets[1]:
        raise ValueError("FSS evaluator snapshot replicas are not identical")
