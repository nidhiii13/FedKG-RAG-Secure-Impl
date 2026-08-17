"""Owner-blind evidence handles, and detection of the allocation that leaks.

The leak
--------
Contribution hiding is a property **against the servers**: the circuit emits a
fixed number of frontier slots per owner regardless of how many matched, so two
colluding servers cannot tell which owner supplied an answer.

It says nothing about the **client**. ``examples/ten_query`` originally allocated
evidence handles per owner -- ``owner_a`` 101-105, ``owner_b`` 201-205,
``owner_c`` 301-306 -- so a returned handle named its contributing owner
outright, and counting handles per range recovered how much each owner
contributed. That fixture has since been reallocated using
``allocate_owner_blind_handles`` below, and ``handles_leak_owner`` is what
verifies it.

That is a property of the **handle allocation policy**, not of the circuit. The
circuit cannot fix it: the client is supposed to receive the handle in order to
fetch the evidence.

The fix, and why it needs no coordination
-----------------------------------------
Draw each handle uniformly at random from the whole evidence space instead of
from an owner-specific range. With ``evidence_bits`` typically 50, the space is
about 1.1e15, so for a federation holding even 10^6 edges the probability that
any two handles collide is on the order of 1e-3, and it falls quadratically as
the space grows.

Crucially this needs **no coordination between owners**. Each owner draws its own
handles independently, exactly as it already prepares its own shares
independently, and the resulting allocation carries no owner signal. That
preserves the deployment property the whole design rests on.

What this does not fix
----------------------
Per-owner data *volume* still leaks through the public page budget ``B_i``; that
is a separate leak addressed by ``volume_hiding.py``. And a client that can
observe handles across many queries may still learn the *number of distinct
handles* in play, which bounds the federation's size -- the same quantity pooling
leaves public.
"""

from __future__ import annotations

import secrets
from collections import Counter
from typing import Any


def allocate_owner_blind_handles(
    edges: list[dict[str, Any]],
    evidence_bits: int,
    *,
    rng: secrets.SystemRandom | None = None,
) -> list[dict[str, Any]]:
    """Return ``edges`` with evidence handles redrawn owner-blind.

    Handles are drawn uniformly from ``[1, 2**evidence_bits)``; zero is reserved
    as the dummy handle, exactly as the packing layer expects. Each owner runs
    this on its own edges alone.
    """

    if evidence_bits < 2:
        raise ValueError("evidence_bits must leave room for a nonzero handle")
    generator = rng or secrets.SystemRandom()
    span = (1 << evidence_bits) - 1
    seen: set[int] = set()
    result: list[dict[str, Any]] = []
    for edge in edges:
        if not isinstance(edge, dict) or "evidence" not in edge:
            raise ValueError("every edge must carry an evidence handle")
        # Redraw on a local collision so one owner never emits a duplicate; a
        # collision across owners is possible but negligible, and harmless
        # because handles are opaque identifiers rather than addresses.
        for _ in range(64):
            handle = generator.randrange(1, span + 1)
            if handle not in seen:
                break
        else:
            raise ValueError(
                "could not draw a fresh handle; evidence_bits is too small for "
                f"{len(edges)} edges"
            )
        seen.add(handle)
        result.append({**edge, "evidence": handle})
    return result


def handle_ranges(
    owner_edges: dict[str, list[dict[str, Any]]],
) -> dict[str, tuple[int, int]]:
    """Minimum and maximum handle each owner uses."""

    ranges: dict[str, tuple[int, int]] = {}
    for owner, edges in owner_edges.items():
        handles = [edge["evidence"] for edge in edges]
        if handles:
            ranges[owner] = (min(handles), max(handles))
    return ranges


def handles_leak_owner(
    owner_edges: dict[str, list[dict[str, Any]]],
    *,
    evidence_bits: int | None = None,
) -> dict[str, Any]:
    """Detect an allocation from which the client can infer the owner.

    Two independent tells are checked, because the obvious one alone is not
    enough:

    **Disjoint ranges.** If no two owners' handle intervals overlap, a handle's
    value alone identifies its owner. This is the failure the bundled fixtures
    exhibit, and the one that occurs in practice from per-owner numbering.

    **Implausible cross-owner duplication.** Independent uniform draws from a
    large space essentially never collide, so repeated handles mean the draws
    were not independent. The failure mode this catches is real and was found by
    running this detector on its own remedy: seeding every owner's generator
    identically produces overlapping ranges -- passing the first check -- while
    in fact emitting the *same handle sequence* for every owner, which is worse
    than per-owner numbering rather than better.

    Neither check is a proof of blindness. An allocation could interleave, avoid
    collisions, and still correlate, for instance by giving each owner a distinct
    residue class. These catch the failures that actually happen.
    """

    ranges = handle_ranges(owner_edges)
    if len(ranges) < 2:
        return {
            "leaks": False,
            "reason": "fewer than two owners hold edges; nothing to distinguish",
            "ranges": ranges,
        }

    spans = sorted(ranges.items(), key=lambda item: item[1][0])
    disjoint = all(
        spans[i][1][1] < spans[i + 1][1][0] for i in range(len(spans) - 1)
    )

    # A second, weaker tell: every handle appearing in exactly one owner and the
    # owners' handle sets being separable by a single threshold.
    all_handles: Counter[int] = Counter()
    for edges in owner_edges.values():
        all_handles.update(edge["evidence"] for edge in edges)
    duplicates = sum(1 for count in all_handles.values() if count > 1)

    # Independent uniform draws from a space of size S essentially never
    # collide while the handle count is far below sqrt(S), so any duplication
    # at these sizes means the draws were not independent.
    total = sum(all_handles.values())
    suspicious_duplication = False
    if evidence_bits is not None and duplicates:
        space = (1 << evidence_bits) - 1
        expected = total * total / (2 * space) if space else float("inf")
        suspicious_duplication = duplicates > max(1.0, 10 * expected)

    leaks = disjoint or suspicious_duplication
    if disjoint:
        reason = "owners occupy disjoint handle ranges, so a handle names its owner"
    elif suspicious_duplication:
        reason = (
            f"{duplicates} handles are shared across owners, far more than "
            "independent uniform draws would produce; the generators are "
            "correlated, most likely seeded identically"
        )
    else:
        reason = "handle ranges overlap, so a handle does not name its owner"

    return {
        "leaks": leaks,
        "reason": reason,
        "disjoint_ranges": disjoint,
        "suspicious_duplication": suspicious_duplication,
        "ranges": ranges,
        "cross_owner_duplicate_handles": duplicates,
        "remedy": (
            "allocate_owner_blind_handles draws uniformly from the whole "
            "evidence space, independently per owner and with no coordination"
        ),
    }
