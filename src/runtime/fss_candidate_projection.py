"""Project two-party DPF evaluations directly into padded candidate slots."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Mapping, Sequence

from src.crypto.dpf_domain import DPF_MODULUS


@dataclass(frozen=True)
class CandidateProjection:
    """Public routing from opaque evaluator points to opaque candidate slots."""

    slot_handles: tuple[str, ...]
    point_weights: Mapping[str, Mapping[str, int]]
    modulus: int = DPF_MODULUS

    @classmethod
    def from_mapping(cls, payload: Mapping[str, object]) -> "CandidateProjection":
        slots = payload.get("slot_handles")
        weights = payload.get("point_weights")
        if not isinstance(slots, list) or not all(isinstance(slot, str) for slot in slots):
            raise ValueError("projection slot_handles must be an array of strings")
        if not isinstance(weights, dict):
            raise ValueError("projection point_weights must be an object")
        normalized_weights = {}
        for point, slot_weights in weights.items():
            if not isinstance(point, str) or not isinstance(slot_weights, dict):
                raise ValueError("projection point weights must map strings to objects")
            normalized_weights[point] = dict(slot_weights)
        projection = cls(tuple(slots), normalized_weights)
        projection.validate()
        return projection

    def validate(self, universe_points: Sequence[str] | None = None) -> None:
        if not self.slot_handles:
            raise ValueError("candidate projection requires at least one slot")
        if len(self.slot_handles) != len(set(self.slot_handles)):
            raise ValueError("candidate projection slot handles must be unique")
        slots = set(self.slot_handles)
        universe = set(universe_points) if universe_points is not None else None
        for point, weights in self.point_weights.items():
            if universe is not None and point not in universe:
                raise ValueError("candidate projection references a point outside the evaluator universe")
            if not isinstance(weights, Mapping):
                raise ValueError("candidate projection weights must be mappings")
            for slot, weight in weights.items():
                if slot not in slots:
                    raise ValueError("candidate projection references an unknown slot")
                if not isinstance(weight, int) or isinstance(weight, bool):
                    raise ValueError("candidate projection weights must be integers")
                if weight < 0 or weight >= self.modulus:
                    raise ValueError("candidate projection weight is outside the DPF field")

    def digest(self) -> str:
        self.validate()
        payload = {
            "version": "fedkg-fss-candidate-projection-v1",
            "modulus": self.modulus,
            "slot_handles": list(self.slot_handles),
            "point_weights": {
                point: dict(sorted(weights.items()))
                for point, weights in sorted(self.point_weights.items())
            },
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(encoded.encode("ascii")).hexdigest()

    def project(self, points: Sequence[str], eval_shares: Sequence[int]) -> list[int]:
        if len(points) != len(eval_shares):
            raise ValueError("point and evaluation-share vectors must have equal length")
        self.validate(points)
        slot_indexes = {slot: index for index, slot in enumerate(self.slot_handles)}
        projected = [0] * len(self.slot_handles)
        for point, eval_share in zip(points, eval_shares):
            if not isinstance(eval_share, int) or isinstance(eval_share, bool):
                raise ValueError("DPF evaluation shares must be integers")
            for slot, weight in self.point_weights.get(point, {}).items():
                index = slot_indexes[slot]
                projected[index] = (projected[index] + eval_share * weight) % self.modulus
        return projected


@dataclass(frozen=True)
class ProjectedFssEvaluatorResponse:
    request_id: str
    evaluator_id: str
    evaluator_index: int
    domain: str
    universe_digest: str
    projection_digest: str
    slot_handles: tuple[str, ...]
    candidate_slot_shares: list[int]

    @classmethod
    def from_mapping(cls, payload: Mapping[str, object]) -> "ProjectedFssEvaluatorResponse":
        required_strings = (
            "request_id",
            "evaluator_id",
            "domain",
            "universe_digest",
            "projection_digest",
        )
        if not all(isinstance(payload.get(name), str) for name in required_strings):
            raise ValueError("projected response is missing string metadata")
        evaluator_index = payload.get("evaluator_index")
        slots = payload.get("slot_handles")
        shares = payload.get("candidate_slot_shares")
        if evaluator_index not in (0, 1):
            raise ValueError("projected response evaluator_index must be 0 or 1")
        if not isinstance(slots, list) or not all(isinstance(slot, str) for slot in slots):
            raise ValueError("projected response slot_handles must be an array of strings")
        if not isinstance(shares, list) or not all(
            isinstance(share, int) and not isinstance(share, bool) for share in shares
        ):
            raise ValueError("projected response candidate_slot_shares must be integers")
        return cls(
            request_id=payload["request_id"],  # type: ignore[arg-type]
            evaluator_id=payload["evaluator_id"],  # type: ignore[arg-type]
            evaluator_index=evaluator_index,
            domain=payload["domain"],  # type: ignore[arg-type]
            universe_digest=payload["universe_digest"],  # type: ignore[arg-type]
            projection_digest=payload["projection_digest"],  # type: ignore[arg-type]
            slot_handles=tuple(slots),
            candidate_slot_shares=list(shares),
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "request_id": self.request_id,
            "evaluator_id": self.evaluator_id,
            "evaluator_index": self.evaluator_index,
            "domain": self.domain,
            "universe_digest": self.universe_digest,
            "projection_digest": self.projection_digest,
            "slot_handles": list(self.slot_handles),
            "candidate_slot_shares": self.candidate_slot_shares,
        }


@dataclass(frozen=True)
class CombinedCandidateSlots:
    request_id: str
    domain: str
    slot_handles: tuple[str, ...]
    values: list[int]
    universe_digest: str
    projection_digest: str

    @property
    def nonzero_slots(self) -> dict[str, int]:
        return {
            slot: value
            for slot, value in zip(self.slot_handles, self.values)
            if value != 0
        }


@dataclass(frozen=True)
class ProjectedFssCoordinator:
    modulus: int = DPF_MODULUS

    def combine(
        self,
        responses: Sequence[ProjectedFssEvaluatorResponse],
    ) -> CombinedCandidateSlots:
        if len(responses) != 2:
            raise ValueError("exactly two projected FSS evaluator responses are required")
        by_index = {response.evaluator_index: response for response in responses}
        if set(by_index) != {0, 1} or len(by_index) != 2:
            raise ValueError("projected responses must contain evaluator indices 0 and 1")
        left, right = by_index[0], by_index[1]
        for attribute in (
            "request_id",
            "domain",
            "universe_digest",
            "projection_digest",
            "slot_handles",
        ):
            if getattr(left, attribute) != getattr(right, attribute):
                raise ValueError(f"projected evaluator response mismatch: {attribute}")
        if len(left.candidate_slot_shares) != len(left.slot_handles):
            raise ValueError("evaluator 0 returned an invalid candidate-slot vector length")
        if len(right.candidate_slot_shares) != len(right.slot_handles):
            raise ValueError("evaluator 1 returned an invalid candidate-slot vector length")
        values = [
            (left_share + right_share) % self.modulus
            for left_share, right_share in zip(
                left.candidate_slot_shares,
                right.candidate_slot_shares,
            )
        ]
        return CombinedCandidateSlots(
            request_id=left.request_id,
            domain=left.domain,
            slot_handles=left.slot_handles,
            values=values,
            universe_digest=left.universe_digest,
            projection_digest=left.projection_digest,
        )
