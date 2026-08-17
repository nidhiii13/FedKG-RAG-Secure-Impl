"""Tests for owner-blind evidence handles.

Contribution hiding holds against the servers by construction, but against the
*client* it depends entirely on how handles are allocated. Per-owner numbering
hands the client the contributing owner for free. These tests pin both the
detection of that failure and the remedy.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest

from doram_t2_3pc.evidence_handles import (
    allocate_owner_blind_handles,
    handle_ranges,
    handles_leak_owner,
)


FIXTURE = Path("doram_t2_3pc/examples/ten_query")
OWNERS = ("owner_a", "owner_b", "owner_c")


def _bundled() -> dict[str, list[dict]]:
    return {o: json.loads((FIXTURE / f"{o}.json").read_text()) for o in OWNERS}


def test_bundled_fixture_is_owner_blind():
    """The shipped fixture must not leak the contributing owner to the client.

    It previously allocated 101-105 / 201-205 / 301-306, one range per owner,
    which named the owner outright. It has since been reallocated owner-blind.
    """

    report = handles_leak_owner(_bundled(), evidence_bits=50)
    assert report["leaks"] is False
    assert report["disjoint_ranges"] is False
    assert report["cross_owner_duplicate_handles"] == 0
    # Ranges must overlap, which is what stops a handle naming its owner.
    ranges = handle_ranges(_bundled())
    lows = [lo for lo, _ in ranges.values()]
    highs = [hi for _, hi in ranges.values()]
    assert max(lows) < min(highs)


def test_per_owner_numbering_is_detected_as_leaking():
    """Detection is proven on a constructed leak, not on the shipped fixture.

    This is the allocation the fixture used to have, and the one a naive
    implementation reaches for.
    """

    leaky = {
        owner: [
            {**edge, "evidence": 100 * (index + 1) + position + 1}
            for position, edge in enumerate(edges)
        ]
        for index, (owner, edges) in enumerate(_bundled().items())
    }
    report = handles_leak_owner(leaky, evidence_bits=50)
    assert report["leaks"] is True
    assert report["disjoint_ranges"] is True
    assert "names its owner" in report["reason"]


def test_owner_blind_allocation_removes_the_leak():
    edges = _bundled()
    blind = {
        owner: allocate_owner_blind_handles(
            rows, 50, rng=random.Random(100 + index)
        )
        for index, (owner, rows) in enumerate(edges.items())
    }
    report = handles_leak_owner(blind, evidence_bits=50)
    assert report["leaks"] is False
    assert report["disjoint_ranges"] is False
    assert report["cross_owner_duplicate_handles"] == 0


def test_identically_seeded_generators_are_detected():
    """Found by running the detector on its own remedy.

    Overlapping ranges pass the obvious check while every owner emits the SAME
    handle sequence, which is worse than per-owner numbering rather than better.
    A range check alone would call this fixed.
    """

    edges = _bundled()
    same_seed = {
        owner: allocate_owner_blind_handles(rows, 50, rng=random.Random(7))
        for owner, rows in edges.items()
    }
    report = handles_leak_owner(same_seed, evidence_bits=50)
    assert report["disjoint_ranges"] is False    # the obvious check passes
    assert report["suspicious_duplication"] is True
    assert report["leaks"] is True               # but it still leaks
    assert "correlated" in report["reason"]


def test_allocation_preserves_everything_except_the_handle():
    edges = _bundled()["owner_a"]
    blind = allocate_owner_blind_handles(edges, 50, rng=random.Random(3))
    assert len(blind) == len(edges)
    for original, updated in zip(edges, blind):
        assert updated["evidence"] != original["evidence"]
        for field in ("source", "relation", "target", "score"):
            assert updated[field] == original[field]


def test_handles_are_never_the_reserved_dummy():
    """Zero is the dummy handle the packing layer reserves."""

    blind = allocate_owner_blind_handles(
        _bundled()["owner_b"], 50, rng=random.Random(11)
    )
    assert all(edge["evidence"] > 0 for edge in blind)


def test_allocation_rejects_a_space_too_small_to_be_blind():
    edges = _bundled()["owner_a"]
    with pytest.raises(ValueError, match="evidence_bits"):
        allocate_owner_blind_handles(edges, 1)


def test_single_owner_has_nothing_to_distinguish():
    report = handles_leak_owner({"owner_a": _bundled()["owner_a"]})
    assert report["leaks"] is False
    assert "fewer than two owners" in report["reason"]


def test_detector_reports_its_own_remedy():
    report = handles_leak_owner(_bundled(), evidence_bits=50)
    assert "allocate_owner_blind_handles" in report["remedy"]
    assert "no coordination" in report["remedy"]
