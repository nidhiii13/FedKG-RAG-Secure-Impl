"""XOR candidate projection: semantics, digests, and builder conversion."""

from __future__ import annotations

import pytest

from src.aggregation.prio3_candidates import SessionCandidateHandleProvider

from multiparty_fss.errors import ProjectionError
from multiparty_fss.projection import (
    XorCandidateProjection,
    build_xor_projection,
)


def _projection() -> XorCandidateProjection:
    return XorCandidateProjection(
        slot_handles=("slot-a", "slot-b", "slot-pad"),
        point_slots={"aa11": ("slot-a",), "bb22": ("slot-b",), "cc33": ("slot-a",)},
    )


def test_projection_xors_shares_into_slots():
    projection = _projection()
    points = ["aa11", "bb22", "cc33"]
    shares = [5, 9, 3]
    assert projection.project(points, shares) == [5 ^ 3, 9, 0]


def test_projection_rejects_unknown_slot_and_duplicate_routing():
    with pytest.raises(ProjectionError, match="unknown slot"):
        XorCandidateProjection(("s",), {"aa": ("t",)}).validate()
    with pytest.raises(ProjectionError, match="twice"):
        XorCandidateProjection(("s",), {"aa": ("s", "s")}).validate()


def test_projection_rejects_point_outside_universe():
    # The projection routes bb22/cc33, but the evaluated universe contains
    # only aa11 — a routed-but-not-evaluated point must be refused.
    projection = _projection()
    with pytest.raises(ProjectionError, match="outside"):
        projection.project(["aa11"], [1])


def test_projection_rejects_out_of_group_share():
    projection = _projection()
    with pytest.raises(ProjectionError, match="64-bit"):
        projection.project(["aa11", "bb22", "cc33"], [1, 2, 1 << 64])
    with pytest.raises(ProjectionError, match="length"):
        projection.project(["aa11"], [1, 2])


def test_digest_is_stable_and_binds_content():
    first = _projection().digest()
    assert first == _projection().digest()
    other = XorCandidateProjection(
        slot_handles=("slot-a", "slot-b", "slot-pad"),
        point_slots={"aa11": ("slot-b",), "bb22": ("slot-b",), "cc33": ("slot-a",)},
    ).digest()
    assert first != other


def test_from_mapping_requires_version():
    payload = _projection().as_dict()
    round_tripped = XorCandidateProjection.from_mapping(payload)
    assert round_tripped.digest() == _projection().digest()

    del payload["version"]
    with pytest.raises(ProjectionError, match="version"):
        XorCandidateProjection.from_mapping(payload)

    legacy_shape = {  # legacy additive projection has no version field
        "slot_handles": ["s"],
        "point_weights": {"aa": {"s": 1}},
    }
    with pytest.raises(ProjectionError):
        XorCandidateProjection.from_mapping(legacy_shape)


def test_build_from_opaque_index(snapshot):
    from src.party.opaque_index_snapshot import ReplicatedEvaluatorIndex

    index = ReplicatedEvaluatorIndex((snapshot,))
    handles = SessionCandidateHandleProvider(b"0123456789abcdef", b"nonce-0123456789")
    built = build_xor_projection(index, handles, "entity", capacity=16)
    assert len(built.projection.slot_handles) == 16
    universe = index.entity_points
    built.projection.validate(universe)
    # every entity point routes to exactly one candidate slot
    for point in universe:
        assert len(built.projection.point_slots[point]) == 1
    # capacity smaller than the candidate set fails closed
    with pytest.raises(ValueError):
        build_xor_projection(index, handles, "entity", capacity=1)
