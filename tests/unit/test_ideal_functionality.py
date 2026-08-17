"""Structural checks backing the proof sketch in IDEAL_FUNCTIONALITY.md.

These constrain the generated circuit. They are not a simulation proof and
cannot become one: no test establishes that a protocol composes securely. What
they do establish is that the circuit has the shape the sketch assumes, and that
a later edit cannot quietly take that shape away.

Each test names the claim from IDEAL_FUNCTIONALITY.md section 5 that it backs.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from doram_t2_3pc.page_program import render_program
from doram_t2_3pc.relation_pages import RelationPageConfig, build_owner_page_layout


FIXTURE = Path("doram_t2_3pc/examples/ten_query")
SPEC = Path("doram_t2_3pc/IDEAL_FUNCTIONALITY.md")


@pytest.fixture
def config() -> RelationPageConfig:
    return RelationPageConfig.load(FIXTURE / "config_relation_pages.json")


def _with_layout(tmp_path: Path, **layout) -> RelationPageConfig:
    raw = json.loads((FIXTURE / "config_relation_pages.json").read_text())
    raw["relation_page_layout"] = {**raw["relation_page_layout"], **layout}
    path = tmp_path / f"cfg-{abs(hash(tuple(sorted(layout.items()))))}.json"
    path.write_text(json.dumps(raw))
    return RelationPageConfig.load(path)


# --------------------------------------------------------------------------
# Claim (b): the instruction trace is a function of the public parameters alone
# --------------------------------------------------------------------------


def test_circuit_has_no_secret_dependent_control_flow(config: RelationPageConfig):
    """A branch on a secret would make the trace depend on the data."""

    source = render_program(config, 3)
    # MP-SPDZ's runtime-branching constructs. Their absence means every loop
    # bound and every branch is a Python-level (public) decision at compile time.
    for construct in ("@if_", "@while_", "@do_while", "if_e(", "crash("):
        assert construct not in source, (
            f"{construct} introduces data-dependent control flow"
        )


def test_every_table_read_is_a_full_width_scan(config: RelationPageConfig):
    """Partial reads would make the memory trace depend on the secret address."""

    source = render_program(config, 2)
    # The directory scan is bounded by DIRECTORY_ROWS and the pool scan by
    # PAGE_BUDGET, both public constants, never by a secret quantity.
    assert "DIRECTORY_ROWS,\n" in source
    assert "PAGE_BUDGET,\n" in source
    assert "demux_matrix(" in source
    # An address must never be opened to index memory directly.
    assert not re.search(r"\[\s*\w+\.reveal\(\)", source)


def test_circuit_text_depends_only_on_public_parameters(tmp_path: Path):
    """Two layouts with identical public parameters must generate one circuit.

    This is the operational form of "the trace is a function of L": the circuit
    is derived from the configuration, and the configuration is public.
    """

    raw = json.loads((FIXTURE / "config_relation_pages.json").read_text())
    first = tmp_path / "a.json"
    second = tmp_path / "b.json"
    first.write_text(json.dumps(raw))
    # Same public parameters, different key order in the serialized file.
    second.write_text(json.dumps(raw, sort_keys=True, indent=4))

    a = render_program(RelationPageConfig.load(first), 4)
    b = render_program(RelationPageConfig.load(second), 4)
    assert a == b


# --------------------------------------------------------------------------
# Claim (c): nothing is opened except freshly masked output shares
# --------------------------------------------------------------------------


def test_only_masked_output_shares_are_opened(config: RelationPageConfig):
    source = render_program(config, 5)
    assert ".reveal()" not in source, "a bare reveal opens a value to all servers"
    assert source.count("reveal_to(") == 3, (
        "expected exactly one masked reveal per server and nothing else"
    )


def test_each_output_share_is_freshly_masked(config: RelationPageConfig):
    """Two of three output shares must be uniform and independent of the value."""

    source = render_program(config, 1)
    emitter = source.split("def emit_output_shares(")[1].split("\n\n")[0]
    assert emitter.count("sint.get_random()") == 2
    assert "share_2 = value - share_0 - share_1" in emitter
    for server in range(3):
        assert f"reveal_to({server})" in emitter


# --------------------------------------------------------------------------
# Claim (d): contribution hiding is structural
# --------------------------------------------------------------------------


def test_compaction_emits_a_fixed_width_per_owner(config: RelationPageConfig):
    """Occupancy must ride in secret bits, never in the emitted width."""

    source = render_program(config, 2)
    assert "for compact_slot in range(FRONTIER_PER_OWNER):" in source
    # The loop bound is the public declared frontier, not anything data-derived.
    assert "FRONTIER_PER_OWNER = " in source
    # Validity is carried as a secret value, not used to size anything.
    assert "frontier_valid[compact_flat] = found" in source


def test_circuit_is_identical_regardless_of_owner_occupancy(tmp_path: Path):
    """An owner with no matches must be indistinguishable from a full one.

    The circuit is generated from public parameters only, so this holds by
    construction; the test pins it so a future data-dependent optimization
    cannot silently break contribution hiding.
    """

    config = RelationPageConfig.load(FIXTURE / "config_relation_pages.json")
    baseline = render_program(config, 2)

    empty_owner = build_owner_page_layout(config, "owner_a", [])
    full_owner = build_owner_page_layout(
        config,
        "owner_a",
        json.loads((FIXTURE / "owner_a.json").read_text()),
    )
    # Different occupancy...
    assert empty_owner.realized_page_count != full_owner.realized_page_count
    # ...but the pool shape, the directory shape, and therefore the circuit are
    # unchanged. Realized occupancy is private; only the declared budget is not.
    assert len(empty_owner.pages) == len(full_owner.pages)
    assert len(empty_owner.directory) == len(full_owner.directory)
    assert render_program(config, 2) == baseline


# --------------------------------------------------------------------------
# Bounds are fail-closed, which is what makes compaction lossless
# --------------------------------------------------------------------------


def test_preparation_rejects_an_owner_exceeding_the_dependent_read_bound(
    tmp_path: Path,
):
    config = _with_layout(tmp_path, page_size=4, pages_per_key=1, frontier_per_owner=1)
    edges = [
        {"source": "alice", "relation": "referred_to", "target": t,
         "evidence": i + 1, "score": 1}
        for i, t in enumerate(("bob", "carol"))
    ]
    with pytest.raises(ValueError, match="frontier_per_owner"):
        build_owner_page_layout(config, "owner_a", edges)


def test_preparation_rejects_an_owner_exceeding_the_storage_bound(tmp_path: Path):
    """B1 and B2 are not independent: B1 is the binding one when f == p*m.

    Because ``frontier_per_owner`` is itself constrained to at most
    ``page_size * pages_per_key``, any key that overflows storage also overflows
    the dependent-read bound. The storage check is ordered first, so it is the
    one that reports. This test pins that ordering, since a silent reordering
    would change which diagnostic an operator sees.
    """

    config = _with_layout(tmp_path, page_size=1, pages_per_key=1, frontier_per_owner=1)
    assert config.pages.effective_frontier_per_owner == config.pages.slots_per_key
    edges = [
        {"source": "alice", "relation": "referred_to", "target": t,
         "evidence": i + 1, "score": 1}
        for i, t in enumerate(("bob", "carol"))
    ]
    with pytest.raises(ValueError, match="pages_per_key"):
        build_owner_page_layout(config, "owner_a", edges)


# --------------------------------------------------------------------------
# The specification must keep saying what it does not prove
# --------------------------------------------------------------------------


def test_specification_does_not_claim_to_be_a_proof():
    """A simulator now exists, so the disclaimer had to change -- not weaken.

    The original assertion looked for "no simulator". That became false when
    simulator.py was written, and this guard failing is what surfaced it. The
    invariant is not that a simulator is absent; it is that the document keeps
    distinguishing a simulator from a proof.
    """

    import re

    # Collapse whitespace: these phrases wrap across lines in the markdown, and
    # a line break should not be able to defeat the guard.
    lowered = re.sub(r"\s+", " ", SPEC.read_text(encoding="utf-8")).lower()
    assert "not a proof" in lowered
    # The two things that make it not a proof must both stay stated.
    assert "no reduction has been carried out" in lowered
    assert "black box" in lowered
    assert "simulator is not a simulation proof" in lowered


def test_specification_records_the_client_side_contribution_leak():
    """The evidence-handle leak must stay documented; it is easy to lose."""

    text = SPEC.read_text(encoding="utf-8")
    assert "against the servers" in text
    assert "evidence handle" in text.lower()
    # The concrete fixture evidence must stay cited, so the claim is checkable.
    assert "101" in text and "201" in text


def test_fixture_evidence_handles_are_owner_blind():
    """Section 8's remedy is applied to the shipped fixture, not just offered.

    This previously asserted the OPPOSITE -- that handles still partitioned by
    owner -- pinning the documented gap so it could not be forgotten. The gap is
    now closed, so the assertion inverts.
    """

    from doram_t2_3pc.evidence_handles import handles_leak_owner

    edges = {
        owner: json.loads((FIXTURE / f"{owner}.json").read_text())
        for owner in ("owner_a", "owner_b", "owner_c")
    }
    assert handles_leak_owner(edges, evidence_bits=50)["leaks"] is False



# --------------------------------------------------------------------------
# Definition 1: contribution hiding
# --------------------------------------------------------------------------


def test_contribution_hiding_is_stated_as_a_definition():
    """It must be citable, not merely argued in prose."""

    text = SPEC.read_text(encoding="utf-8")
    assert "Definition 1 (Contribution hiding)" in text
    # The quantifier and the equivalence both have to be present.
    assert "View_C(G, q)" in text and "View_C(G', q)" in text
    assert "at most two servers" in text


def test_definition_scopes_itself_away_from_volume_and_the_client():
    """The two things it is easiest to over-read it as covering."""

    text = SPEC.read_text(encoding="utf-8")
    section = text.split("Definition 1 (Contribution hiding)")[1]
    section = section.split("## 5.")[0]
    assert "does not cover" in section
    assert "volume" in section.lower()
    assert "client" in section.lower()
    assert "volume_hiding.py" in section


def test_owner_blind_handles_are_offered_as_the_client_side_remedy():
    text = SPEC.read_text(encoding="utf-8")
    assert "allocate_owner_blind_handles" in text
    assert "no coordination" in text
    # The detector's second check exists because the first was insufficient.
    assert "same handle sequence" in text
