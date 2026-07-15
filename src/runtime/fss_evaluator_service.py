"""Role-separated FSS evaluator over a replicated opaque index store."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Mapping, Sequence

from src.crypto.dpf import DpfBackend, DpfKeyShare
from src.party.opaque_index_snapshot import OpaqueIndexSnapshot, ReplicatedEvaluatorIndex
from src.runtime.fss_candidate_projection import (
    CandidateProjection,
    ProjectedFssEvaluatorResponse,
)

EvaluationDomain = Literal["entity", "relation", "type", "frontier"]


@dataclass(frozen=True)
class FssEvaluatorStore:
    evaluator_id: str
    evaluator_index: int
    index: ReplicatedEvaluatorIndex

    @classmethod
    def load(cls, root: str | Path, expected_evaluator_id: str | None = None) -> "FssEvaluatorStore":
        store_root = Path(root)
        manifest = json.loads((store_root / "manifest.json").read_text())
        if not isinstance(manifest, dict):
            raise ValueError("evaluator manifest must be a JSON object")
        evaluator_id = manifest.get("evaluator_id")
        evaluator_index = manifest.get("evaluator_index")
        records = manifest.get("snapshots")
        if not isinstance(evaluator_id, str) or not evaluator_id:
            raise ValueError("evaluator manifest requires evaluator_id")
        if evaluator_index not in (0, 1):
            raise ValueError("evaluator_index must be 0 or 1")
        if expected_evaluator_id is not None and evaluator_id != expected_evaluator_id:
            raise ValueError("evaluator store identity does not match configured role")
        if not isinstance(records, list) or not records:
            raise ValueError("evaluator manifest requires snapshot records")

        snapshots = []
        for record in records:
            if not isinstance(record, dict):
                raise ValueError("invalid evaluator snapshot record")
            relative_path = record.get("relative_path")
            expected_digest = record.get("digest")
            expected_partition = record.get("partition_id")
            if not all(isinstance(value, str) and value for value in (
                relative_path,
                expected_digest,
                expected_partition,
            )):
                raise ValueError("snapshot records require path, digest, and partition ID")
            path = (store_root / relative_path).resolve()
            if store_root.resolve() not in path.parents:
                raise ValueError("snapshot path escapes evaluator store")
            snapshot = OpaqueIndexSnapshot.from_json(path)
            if snapshot.partition_id != expected_partition:
                raise ValueError("snapshot partition ID does not match manifest")
            if snapshot.digest() != expected_digest:
                raise ValueError("snapshot digest does not match manifest")
            snapshots.append(snapshot)
        return cls(evaluator_id, evaluator_index, ReplicatedEvaluatorIndex(tuple(snapshots)))

    def points_for(self, domain: EvaluationDomain) -> list[str]:
        if domain == "entity":
            return self.index.entity_points
        if domain == "relation":
            return self.index.relation_points
        if domain == "type":
            return sorted(
                {type_id for snapshot in self.index.snapshots for type_id in snapshot.type_index}
            )
        if domain == "frontier":
            return self.index.frontier_points
        raise ValueError(f"unsupported evaluation domain: {domain}")


@dataclass(frozen=True)
class FssEvaluatorRequest:
    request_id: str
    domain: EvaluationDomain
    key_share: DpfKeyShare


@dataclass(frozen=True)
class FssEvaluatorResponse:
    request_id: str
    evaluator_id: str
    evaluator_index: int
    domain: EvaluationDomain
    universe_digest: str
    point_count: int
    value_shares: list[int]

    def as_dict(self) -> dict[str, object]:
        return {
            "request_id": self.request_id,
            "evaluator_id": self.evaluator_id,
            "evaluator_index": self.evaluator_index,
            "domain": self.domain,
            "universe_digest": self.universe_digest,
            "point_count": self.point_count,
            "value_shares": self.value_shares,
        }


@dataclass(frozen=True)
class FssEvaluatorService:
    store: FssEvaluatorStore
    backend: DpfBackend

    def evaluate(self, request: FssEvaluatorRequest) -> FssEvaluatorResponse:
        if not request.request_id:
            raise ValueError("request_id must not be empty")
        if request.key_share.party_id != self.store.evaluator_id:
            raise ValueError("DPF key share is assigned to a different evaluator")
        payload = request.key_share.payload
        if isinstance(payload, Mapping) and payload.get("party") != self.store.evaluator_index:
            raise ValueError("native DPF share index does not match evaluator_index")
        points = self.store.points_for(request.domain)
        eval_many = getattr(self.backend, "eval_many", None)
        if callable(eval_many):
            values = eval_many(request.key_share, points)
        else:
            values = [self.backend.eval(request.key_share, point) for point in points]
        if len(values) != len(points):
            raise ValueError("DPF backend returned an unexpected number of output shares")
        return FssEvaluatorResponse(
            request_id=request.request_id,
            evaluator_id=self.store.evaluator_id,
            evaluator_index=self.store.evaluator_index,
            domain=request.domain,
            universe_digest=universe_digest(points),
            point_count=len(points),
            value_shares=list(values),
        )

    def evaluate_projected(
        self,
        request: FssEvaluatorRequest,
        projection: CandidateProjection,
    ) -> ProjectedFssEvaluatorResponse:
        response = self.evaluate(request)
        points = self.store.points_for(request.domain)
        candidate_slot_shares = projection.project(points, response.value_shares)
        return ProjectedFssEvaluatorResponse(
            request_id=response.request_id,
            evaluator_id=response.evaluator_id,
            evaluator_index=response.evaluator_index,
            domain=response.domain,
            universe_digest=response.universe_digest,
            projection_digest=projection.digest(),
            slot_handles=projection.slot_handles,
            candidate_slot_shares=candidate_slot_shares,
        )



def universe_digest(points: Sequence[str]) -> str:
    digest = hashlib.sha256()
    digest.update(b"fedkg-fss-universe-v1\x00")
    for point in points:
        digest.update(bytes.fromhex(point))
    return digest.hexdigest()
