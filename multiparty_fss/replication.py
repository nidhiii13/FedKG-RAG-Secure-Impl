"""Replicate opaque index snapshots to N multi-party FSS evaluator stores.

Generalizes the write-loop pattern of the legacy two-evaluator module
(src/runtime/opaque_index_replication.py) without touching it. Differences:

- N in [MIN_PARTIES, MAX_PARTIES] evaluators (the legacy module owns N=2);
- the manifest is version-disjoint ("fedkg-mpfss-replica-manifest-v1") and
  additionally binds construction, party_count, threshold, this store's
  party_index, and the full ordered evaluator-ID list, so a loaded store can
  fail closed on any topology inconsistency;
- verification checks that ALL N replicas carry identical snapshot record
  sets and identical topology metadata (the legacy verifier compared only a
  pair).

Party index is the position in `evaluator_ids`; the ordered list is embedded
in every manifest precisely so that reordering a config file cannot silently
reassign indices without every store noticing the mismatch.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from src.party.opaque_index_snapshot import OpaqueIndexSnapshot

from multiparty_fss.errors import StoreError
from multiparty_fss.params import (
    CONSTRUCTION_ID,
    MAX_PARTIES,
    MIN_PARTIES,
    WIRE_VERSION_MANIFEST,
    honest_majority_threshold,
)


@dataclass(frozen=True)
class MpSnapshotRecord:
    partition_id: str
    digest: str
    relative_path: str


@dataclass(frozen=True)
class MpEvaluatorManifest:
    evaluator_id: str
    party_index: int
    party_count: int
    threshold: int
    evaluator_ids: tuple[str, ...]
    snapshots: tuple[MpSnapshotRecord, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "version": WIRE_VERSION_MANIFEST,
            "construction": CONSTRUCTION_ID,
            "evaluator_id": self.evaluator_id,
            "party_index": self.party_index,
            "party_count": self.party_count,
            "threshold": self.threshold,
            "evaluator_ids": list(self.evaluator_ids),
            "snapshots": [
                {
                    "partition_id": record.partition_id,
                    "digest": record.digest,
                    "relative_path": record.relative_path,
                }
                for record in self.snapshots
            ],
        }


def _validate_topology(
    evaluator_ids: Sequence[str], threshold: int | None
) -> tuple[tuple[str, ...], int]:
    ids = tuple(evaluator_ids)
    if not MIN_PARTIES <= len(ids) <= MAX_PARTIES:
        raise StoreError(
            f"multi-party replication requires between {MIN_PARTIES} and "
            f"{MAX_PARTIES} evaluator IDs (N=2 belongs to the legacy path); "
            f"got {len(ids)}"
        )
    if len(set(ids)) != len(ids) or not all(isinstance(x, str) and x for x in ids):
        raise StoreError("evaluator IDs must be unique non-empty strings")
    resolved = (
        honest_majority_threshold(len(ids)) if threshold is None else threshold
    )
    if not 1 <= resolved <= len(ids) - 1:
        raise StoreError(
            f"threshold must satisfy 1 <= t <= N-1; got t={resolved} for N={len(ids)}"
        )
    return ids, resolved


def replicate_opaque_snapshots_multiparty(
    snapshots: Sequence[OpaqueIndexSnapshot],
    evaluator_ids: Sequence[str],
    output_root: str | Path,
    threshold: int | None = None,
) -> Mapping[str, MpEvaluatorManifest]:
    """Write byte-identical snapshot replicas plus an N-party manifest per store."""
    ids, resolved_threshold = _validate_topology(evaluator_ids, threshold)
    if not snapshots:
        raise StoreError("at least one opaque snapshot is required")
    partition_ids = [snapshot.partition_id for snapshot in snapshots]
    if len(partition_ids) != len(set(partition_ids)):
        raise StoreError("opaque snapshot partition IDs must be unique")

    root = Path(output_root)
    ordered_snapshots = sorted(snapshots, key=lambda snapshot: snapshot.partition_id)
    manifests: dict[str, MpEvaluatorManifest] = {}
    for party_index, evaluator_id in enumerate(ids):
        evaluator_root = root / evaluator_id
        records = []
        for snapshot in ordered_snapshots:
            relative_path = f"partitions/{snapshot.partition_id}.json"
            snapshot.write(evaluator_root / relative_path)
            records.append(
                MpSnapshotRecord(
                    partition_id=snapshot.partition_id,
                    digest=snapshot.digest(),
                    relative_path=relative_path,
                )
            )
        manifest = MpEvaluatorManifest(
            evaluator_id=evaluator_id,
            party_index=party_index,
            party_count=len(ids),
            threshold=resolved_threshold,
            evaluator_ids=ids,
            snapshots=tuple(records),
        )
        evaluator_root.mkdir(parents=True, exist_ok=True)
        (evaluator_root / "manifest.json").write_text(
            json.dumps(manifest.as_dict(), indent=2, sort_keys=True)
        )
        manifests[evaluator_id] = manifest
    return manifests


def verify_multiparty_replicas(manifests: Mapping[str, MpEvaluatorManifest]) -> None:
    """All N manifests must agree on topology and carry identical record sets."""
    if not manifests:
        raise StoreError("no evaluator manifests supplied")
    values = list(manifests.values())
    reference = values[0]
    if len(manifests) != reference.party_count:
        raise StoreError(
            f"expected {reference.party_count} evaluator manifests; got {len(manifests)}"
        )
    expected_ids = reference.evaluator_ids
    for manifest in values:
        if manifest.evaluator_ids != expected_ids:
            raise StoreError("evaluator manifests disagree on the evaluator-ID list")
        if manifest.party_count != reference.party_count:
            raise StoreError("evaluator manifests disagree on party_count")
        if manifest.threshold != reference.threshold:
            raise StoreError("evaluator manifests disagree on threshold")
        if manifest.party_index != expected_ids.index(manifest.evaluator_id):
            raise StoreError("evaluator manifest party_index does not match its position")
    reference_records = {
        (record.partition_id, record.digest) for record in reference.snapshots
    }
    for manifest in values[1:]:
        records = {(record.partition_id, record.digest) for record in manifest.snapshots}
        if records != reference_records:
            raise StoreError("multi-party evaluator snapshot replicas are not identical")
