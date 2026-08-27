"""XOR candidate projection for GF(2)^64 output shares.

The legacy CandidateProjection (src/runtime/fss_candidate_projection.py) is a
Z/(2^64)-linear map over ADDITIVE shares and is cryptographically incompatible
with the multi-party path's XOR output group. This module provides the XOR
analogue: each candidate slot receives the XOR of the output shares of the
universe points routed to it. Because point-to-slot routing in this repo is
boolean (a point contributes to a slot with weight exactly 1) and only x =
alpha yields a nonzero function value, the combined slot vector equals the
legacy semantics: beta at slots containing alpha's point, 0 elsewhere.

The slot LAYOUT (candidate handles, padding, collision checks) is neutral
infrastructure and is reused from the legacy builder
(src/runtime/fss_projection_builder.py: OpaqueIndexProjectionBuilder); this
module converts its output, refusing any weight other than exactly 1.

The projection digest is version-disjoint from the legacy digest
("fedkg-mpfss-xor-projection-v1" vs "fedkg-fss-candidate-projection-v1"), so
projections cannot be silently exchanged between the two paths.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Mapping, Sequence

from src.aggregation.prio3_candidates import SessionCandidateHandleProvider
from src.party.opaque_index_snapshot import ReplicatedEvaluatorIndex
from src.runtime.fss_evaluator_service import EvaluationDomain
from src.runtime.fss_projection_builder import OpaqueIndexProjectionBuilder

from multiparty_fss.errors import ProjectionError
from multiparty_fss.params import OUTPUT_BITS

PROJECTION_VERSION = "fedkg-mpfss-xor-projection-v1"
_WORD_MASK = (1 << OUTPUT_BITS) - 1


@dataclass(frozen=True)
class XorCandidateProjection:
    """Public routing from opaque universe points to padded candidate slots."""

    slot_handles: tuple[str, ...]
    point_slots: Mapping[str, tuple[str, ...]]

    @classmethod
    def from_mapping(cls, payload: Mapping[str, object]) -> "XorCandidateProjection":
        if not isinstance(payload, Mapping):
            raise ProjectionError("projection must be a JSON object")
        if set(payload) != {"version", "slot_handles", "point_slots"}:
            raise ProjectionError(
                "projection requires exactly version, slot_handles, point_slots"
            )
        if payload["version"] != PROJECTION_VERSION:
            raise ProjectionError(
                f"unsupported projection version: {payload['version']!r}"
            )
        slots = payload["slot_handles"]
        point_slots = payload["point_slots"]
        if not isinstance(slots, list) or not all(isinstance(s, str) for s in slots):
            raise ProjectionError("slot_handles must be an array of strings")
        if not isinstance(point_slots, Mapping):
            raise ProjectionError("point_slots must be an object")
        normalized: dict[str, tuple[str, ...]] = {}
        for point, targets in point_slots.items():
            if not isinstance(point, str) or not isinstance(targets, list):
                raise ProjectionError("point_slots must map strings to arrays")
            if not all(isinstance(target, str) for target in targets):
                raise ProjectionError("point_slots targets must be strings")
            normalized[point] = tuple(targets)
        projection = cls(tuple(slots), normalized)
        projection.validate()
        return projection

    def validate(self, universe_points: Sequence[str] | None = None) -> None:
        if not self.slot_handles:
            raise ProjectionError("projection requires at least one slot")
        if len(self.slot_handles) != len(set(self.slot_handles)):
            raise ProjectionError("projection slot handles must be unique")
        slots = set(self.slot_handles)
        universe = set(universe_points) if universe_points is not None else None
        for point, targets in self.point_slots.items():
            if universe is not None and point not in universe:
                raise ProjectionError(
                    "projection references a point outside the evaluator universe"
                )
            if len(targets) != len(set(targets)):
                raise ProjectionError(
                    "projection routes a point to the same slot twice"
                )
            for target in targets:
                if target not in slots:
                    raise ProjectionError("projection references an unknown slot")

    def as_dict(self) -> dict[str, object]:
        return {
            "version": PROJECTION_VERSION,
            "slot_handles": list(self.slot_handles),
            "point_slots": {
                point: list(targets)
                for point, targets in sorted(self.point_slots.items())
            },
        }

    def digest(self) -> str:
        self.validate()
        encoded = json.dumps(
            self.as_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        return hashlib.sha256(encoded.encode("ascii")).hexdigest()

    def project(self, points: Sequence[str], eval_shares: Sequence[int]) -> list[int]:
        """XOR each point's output share into every slot it routes to."""
        if len(points) != len(eval_shares):
            raise ProjectionError(
                "point and evaluation-share vectors must have equal length"
            )
        self.validate(points)
        slot_indexes = {slot: index for index, slot in enumerate(self.slot_handles)}
        projected = [0] * len(self.slot_handles)
        for point, share in zip(points, eval_shares):
            if not isinstance(share, int) or isinstance(share, bool):
                raise ProjectionError("evaluation shares must be integers")
            if not 0 <= share <= _WORD_MASK:
                raise ProjectionError("evaluation share out of the 64-bit group")
            for slot in self.point_slots.get(point, ()):
                projected[slot_indexes[slot]] ^= share
        return projected


@dataclass(frozen=True)
class BuiltXorProjection:
    projection: XorCandidateProjection
    handle_to_candidate_id: Mapping[str, str]

    def candidate_values(self, slot_values: Mapping[str, int]) -> dict[str, int]:
        return {
            self.handle_to_candidate_id[handle]: value
            for handle, value in slot_values.items()
            if handle in self.handle_to_candidate_id and value != 0
        }


def build_xor_projection(
    index: ReplicatedEvaluatorIndex,
    handles: SessionCandidateHandleProvider,
    domain: EvaluationDomain,
    capacity: int,
) -> BuiltXorProjection:
    """Build the padded slot layout with the legacy (neutral) builder, then
    convert its unit-weight routing into the XOR projection format."""
    built = OpaqueIndexProjectionBuilder(index, handles).build(domain, capacity)
    point_slots: dict[str, tuple[str, ...]] = {}
    for point, weights in built.projection.point_weights.items():
        for slot, weight in weights.items():
            if weight != 1:
                raise ProjectionError(
                    "XOR projection requires unit point-to-slot weights"
                )
        point_slots[point] = tuple(sorted(weights))
    projection = XorCandidateProjection(built.projection.slot_handles, point_slots)
    projection.validate()
    return BuiltXorProjection(projection, dict(built.handle_to_candidate_id))
