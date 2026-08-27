"""Regression guards against overclaiming in supported-backend documentation.

The supported backend is a packed batched MPC-oblivious linear scan. It is
O(entity_count) per lookup, has no persistent ORAM state, is semi-honest only,
and its dataset results are bounded-reference equivalence over repeated
executions rather than uncapped dataset accuracy. Prose drifts back toward
stronger words during editing, so these tests fail closed on the specific
claims that a reviewer would treat as unsupported.

Stable machine identifiers (the ``doram_scan_3pc_`` program prefix and the
``DORAM_BATCH_SHARE`` output line format) are deliberately exempt: they are
wire/format names, not assertions about asymptotics, and renaming them would
invalidate already-prepared shares and recorded logs.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest


PACKAGE = Path("doram_t2_3pc")
DOCS = (PACKAGE / "README.md", PACKAGE / "THREAT_MODEL.md")

# Affirmative claims that the implementation does not support. Each pattern is
# written to match an assertion, not a disclaimer: "not a sublinear ORAM" and
# "rather than sublinear" must keep passing.
FORBIDDEN_CLAIMS = (
    (r"\bis a sublinear\b", "claims the backend is sublinear"),
    (r"\bsublinear DORAM\b", "names the backend a sublinear DORAM"),
    (r"\b(?:implements|provides|achieves|offers)\s+(?:a\s+)?sublinear\b",
     "claims sublinear access"),
    (r"\b(?:implements|provides|achieves|offers)\s+(?:a\s+)?persistent\s+"
     r"(?:read/write\s+)?ORAM\b", "claims persistent ORAM state"),
    (r"\bproduction[- ]ready\b", "claims production readiness"),
    (r"\b(?:we|this|it)\s+(?:achieves?|provides?|implements?)\s+malicious\s+"
     r"security\b", "claims malicious security"),
    (r"\bmaliciously[- ]secure backend\b", "claims a malicious-secure backend"),
    (r"\bfull\s+(?:uncapped\s+)?MetaQA\s+(?:accuracy|evaluation|results?)\b",
     "claims full/uncapped MetaQA results"),
    # "the WebQSP evaluation fixture" names a fixture built from WebQSP; it is
    # not a claim to have evaluated on WebQSP. The lookahead keeps the guard
    # aimed at the claim rather than at the noun phrase.
    (r"\bWebQSP\s+(?:evaluation|results?|benchmark)\b(?!\s+fixture)",
     "claims a WebQSP evaluation"),
    (r"\bdistinct[- ]query accuracy\b", "claims distinct-query accuracy"),
)

# Disclaimers whose removal would silently strengthen the documented claim.
REQUIRED_DISCLAIMERS = {
    PACKAGE / "README.md": (
        "packed batched MPC-oblivious linear scan",
        "rather than sublinear",
        "does not implement persistent read/write ORAM state",
    ),
    PACKAGE / "THREAT_MODEL.md": (
        "not as a sublinear or persistent",
        "semi-honest",
    ),
}


def _normalized(path: Path) -> str:
    """Collapse whitespace so wrapped markdown lines still match phrases."""

    return re.sub(r"\s+", " ", path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("document", DOCS, ids=lambda path: path.name)
def test_supported_backend_documentation_makes_no_forbidden_claim(
    document: Path,
):
    text = _normalized(document)
    for pattern, description in FORBIDDEN_CLAIMS:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        assert match is None, (
            f"{document} {description}: {match.group(0)!r}"
        )


@pytest.mark.parametrize("document", DOCS, ids=lambda path: path.name)
def test_required_disclaimers_are_present(document: Path):
    text = _normalized(document)
    for phrase in REQUIRED_DISCLAIMERS[document]:
        assert phrase in text, f"{document} lost the disclaimer {phrase!r}"


def test_guard_detects_a_reintroduced_claim(tmp_path: Path):
    """The guard must actually fire; a vacuous regex would pass silently."""

    sample = "This backend is a sublinear DORAM and is production-ready."
    fired = [
        description
        for pattern, description in FORBIDDEN_CLAIMS
        if re.search(pattern, sample, flags=re.IGNORECASE)
    ]
    assert "claims the backend is sublinear" in fired
    assert "names the backend a sublinear DORAM" in fired
    assert "claims production readiness" in fired


def test_guard_does_not_fire_on_honest_disclaimers():
    honest = (
        "It is O(entity_count) rather than sublinear and it does not implement "
        "persistent read/write ORAM state. This is not a sublinear ORAM."
    )
    for pattern, description in FORBIDDEN_CLAIMS:
        assert re.search(pattern, honest, flags=re.IGNORECASE) is None, (
            f"disclaimer wording wrongly flagged as {description}"
        )


def test_regression_analyzer_reports_reference_matching_not_accuracy():
    """Repeated executions must never be summarized as query accuracy."""

    source = Path("scripts/analyze_doram_regression.py").read_text(
        encoding="utf-8"
    )
    # The analyzer may mention accuracy only to disclaim it.
    for forbidden_key in ('"accuracy"', '"query_accuracy"', '"accuracy_over_completed"'):
        assert forbidden_key not in source, (
            f"analyzer emits {forbidden_key}; use a bounded-reference metric"
        )
    assert "bounded_reference_match_rate" in source
    assert "distinct_query_count" in source


def test_recorded_benchmarks_carry_a_scope_warning():
    """Every recorded measurement must state what it does not generalize to."""

    import json

    benchmarks = sorted((PACKAGE / "benchmarks").glob("*.json"))
    assert benchmarks, "expected at least one recorded benchmark"
    for path in benchmarks:
        document = json.loads(path.read_text(encoding="utf-8"))
        assert isinstance(document, dict)
        warning = document.get("scope_warning") or document.get("scope")
        assert warning, f"{path} has no scope_warning"


def test_experimental_backend_is_labelled_experimental():
    """The paged layout must not read as the supported backend.

    It is executable now, so the guard checks that it still identifies itself
    as experimental and still defers to the packed scan as supported, rather
    than checking that no circuit exists.
    """

    for module in ("relation_pages.py", "page_program.py", "run_pages_mpspdz.py"):
        source = (PACKAGE / module).read_text(encoding="utf-8")
        assert "EXPERIMENTAL" in source, f"{module} is not labelled experimental"
    layout = (PACKAGE / "relation_pages.py").read_text(encoding="utf-8")
    assert "supported* backend remains the packed" in layout


def test_paged_backend_documents_its_additional_leakage():
    """A new public bound must never be introduced silently."""

    layout = (PACKAGE / "relation_pages.py").read_text(encoding="utf-8")
    for term in ("page_size", "pages_per_key", "page_budget"):
        assert term in layout
    assert "Additional public leakage" in layout


def test_paged_benchmark_reports_the_negative_fixture_result():
    """The A/B measurement must not be quietly dropped if it is unflattering."""

    import json

    path = PACKAGE / "benchmarks" / "relation_paged_backend_ab.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["scope_warning"]
    assert "SLOWER" in document["headline_finding"]
    assert document["correctness"]["mpc_matches_paged_cleartext_oracle"] == 10
    assert document["correctness"]["mpc_matches_packed_scan_cleartext_oracle"] == 10
    assert document["what_this_does_not_show"]


def test_no_document_claims_end_to_end_malicious_security():
    """MASCOT runs are measured, but both trust boundaries stay unauthenticated.

    The circuit executes correctly under a malicious-security protocol, which is
    a real and recordable result. It is not the same as the system being
    maliciously secure, and the difference is easy to lose in a rewrite.
    """

    import json

    claims = (
        "maliciously secure",
        "malicious security is achieved",
        "provides malicious security",
        "secure against malicious",
    )
    # These phrases are fine when denied; the guard is against asserting them.
    negations = ("not ", "never ", "no ", "without ")
    for path in sorted((PACKAGE / "benchmarks").glob("*.json")):
        text = path.read_text(encoding="utf-8")
        lowered = text.lower()
        for phrase in claims:
            start = 0
            while (found := lowered.find(phrase, start)) != -1:
                preceding = lowered[max(0, found - 40):found]
                assert any(mark in preceding for mark in negations), (
                    f"{path} asserts '{phrase}' without negating it"
                )
                start = found + len(phrase)
        document = json.loads(text)
        # A benchmark that mentions MASCOT at all must say what it does not cover.
        if "mascot" in lowered:
            disclaimers = json.dumps(
                document.get("what_this_does_NOT_establish", [])
            ).lower()
            assert "unauthenticated" in disclaimers, (
                f"{path} measures MASCOT without recording the unauthenticated "
                "input/output boundaries"
            )


def test_readme_pairs_every_speedup_with_its_negative_result():
    """A crossover has two sides; quoting only the winning one is misleading."""

    readme = (PACKAGE / "README.md").read_text(encoding="utf-8")
    if "23.6x" in readme:
        assert "1.15x slower" in readme, (
            "README quotes the paged speedup without the fixture where it loses"
        )
        assert "narrowing factor" in readme


def test_ablation_switches_cannot_be_set_from_a_configuration():
    """An ablation must never be reachable from a layout file."""

    layout = (PACKAGE / "relation_pages.py").read_text(encoding="utf-8")
    for switch in ("ablate_relation_check", "ablate_window_demux", "ablate_compaction"):
        assert switch not in layout, (
            f"{switch} leaked into the layout configuration module"
        )


def test_leakage_documents_stay_consistent_with_each_other():
    """The two security documents must not drift apart."""

    spec = (PACKAGE / "IDEAL_FUNCTIONALITY.md").read_text(encoding="utf-8")
    abuse = (PACKAGE / "LEAKAGE_ABUSE.md").read_text(encoding="utf-8")

    # Every public parameter named in the leakage function must be analysed.
    for parameter in ("B_i", "f", "p", "m", "E", "R", "Q"):
        assert parameter in abuse, f"{parameter} is in L but not analysed"
    # The abuse analysis must point back at the client-side scope caveat.
    assert "IDEAL_FUNCTIONALITY.md" in abuse
    # The spec must not claim the leakage is harmless.
    assert "LEAKAGE_ABUSE.md" in spec


def test_no_document_claims_the_servers_learn_nothing():
    """The honest claim is bounded leakage, not zero leakage."""

    overclaims = (
        "servers learn nothing",
        "learn nothing about the owners",
        "zero leakage",
        "no leakage",
    )
    # Contexts in which the phrase is being disclaimed rather than asserted.
    negations = (
        "not ", "never ", "would be false", "would be overclaiming",
        "weaker than", "rather than", "stronger than",
    )
    for name in ("IDEAL_FUNCTIONALITY.md", "LEAKAGE_ABUSE.md", "THREAT_MODEL.md",
                 "README.md"):
        lowered = (PACKAGE / name).read_text(encoding="utf-8").lower()
        for phrase in overclaims:
            start = 0
            while (found := lowered.find(phrase, start)) != -1:
                preceding = lowered[max(0, found - 60):found]
                assert any(mark in preceding for mark in negations), (
                    f"{name} asserts '{phrase}' without negating it"
                )
                start = found + len(phrase)


def test_weaker_threat_model_requires_explicit_opt_in():
    """A protocol downgrade must never be selectable by accident."""

    from doram_t2_3pc.protocols import PROTOCOLS, resolve

    weaker = [key for key, p in PROTOCOLS.items() if p.weaker_than_declared]
    assert weaker, "expected at least one weaker-threat-model protocol"
    for key in weaker:
        import pytest as _pytest

        with _pytest.raises(ValueError, match="corrupted server"):
            resolve(key)
        # ...and it must succeed only with the explicit flag.
        assert resolve(key, allow_weaker_threat_model=True).key == key
        assert "WEAKER" in PROTOCOLS[key].summary

    # A protocol matching the declared model needs no opt-in.
    for key, protocol in PROTOCOLS.items():
        if not protocol.weaker_than_declared:
            assert resolve(key).key == key


def test_full_threshold_passive_protocols_are_not_security_downgrades():
    """Changing preprocessing must not silently change the collusion bound."""

    from doram_t2_3pc.protocols import PROTOCOLS
    from doram_t2_3pc.config import HE_SCALABLE_FIELD_PRIME

    expected = {
        "semi": ("semi.sh", "semi-party.x"),
        "hemi": ("hemi.sh", "hemi-party.x"),
        "temi": ("temi.sh", "temi-party.x"),
    }
    for key, (script, binary) in expected.items():
        protocol = PROTOCOLS[key]
        assert protocol.script == script
        assert protocol.binary == binary
        assert protocol.max_corrupted_servers == 2
        assert not protocol.malicious
        assert not protocol.weaker_than_declared
        assert "dishonest majority" in protocol.describe()
        if key in {"hemi", "temi"}:
            assert HE_SCALABLE_FIELD_PRIME % protocol.prime_congruence_modulus == 1


def test_he_protocols_reject_the_mersenne_field_before_launch():
    from doram_t2_3pc.config import HE_SCALABLE_FIELD_PRIME, SCALABLE_FIELD_PRIME
    from doram_t2_3pc.protocols import PROTOCOLS

    import pytest as _pytest

    for key in ("hemi", "temi"):
        with _pytest.raises(ValueError, match="new input shares"):
            PROTOCOLS[key].validate_field_prime(SCALABLE_FIELD_PRIME)
        PROTOCOLS[key].validate_field_prime(HE_SCALABLE_FIELD_PRIME)


def test_protocol_choice_is_not_a_configuration_field():
    """A stored layout must not be able to weaken a run's security."""

    layout = (PACKAGE / "relation_pages.py").read_text(encoding="utf-8")
    for term in ("atlas", "party_binary", "protocol_script", "allow_weaker"):
        assert term not in layout, f"{term} leaked into the layout configuration"


def test_every_public_layout_parameter_appears_in_both_security_documents():
    """Catch a new public bound being added to code but not to the leakage docs.

    This regression exists because global_frontier was added to
    RelationPageParameters, and to a docstring that pointed at
    IDEAL_FUNCTIONALITY.md for its leakage, while neither security document
    mentioned it. The leakage function was silently wrong for any layout that
    used it.
    """

    import dataclasses

    from doram_t2_3pc.relation_pages import RelationPageParameters

    # The security documents use mathematical symbols rather than field names.
    # This mapping is deliberately explicit: adding a field to the layout without
    # extending it fails here, which is the point.
    SYMBOLS = {
        "page_size": "`p`",
        "pages_per_key": "`m`",
        "page_budget": "`B_i`",
        "frontier_per_owner": "`f`",
        "global_frontier": "`g`",
        "directory_buckets": "`b`",
        "bucket_slots": "`s`",
        "partition_residual_by_relation": "`rho`",
    }
    fields = {field.name for field in dataclasses.fields(RelationPageParameters)}
    undocumented = fields - set(SYMBOLS)
    assert not undocumented, (
        f"layout parameters {sorted(undocumented)} have no documented symbol; "
        "add them to SYMBOLS here and to both security documents"
    )

    spec = (PACKAGE / "IDEAL_FUNCTIONALITY.md").read_text(encoding="utf-8")
    abuse = (PACKAGE / "LEAKAGE_ABUSE.md").read_text(encoding="utf-8")
    for name in fields:
        symbol = SYMBOLS[name]
        assert name in spec, (
            f"{name} is not named in IDEAL_FUNCTIONALITY.md"
        )
        assert symbol in spec, (
            f"{name} ({symbol}) is not in the leakage function"
        )
        assert symbol in abuse, (
            f"{name} ({symbol}) is not analysed in LEAKAGE_ABUSE.md"
        )


def test_cross_document_references_resolve():
    """A document must not point at a section of another that does not exist."""

    import re

    for name in ("IDEAL_FUNCTIONALITY.md", "LEAKAGE_ABUSE.md"):
        text = (PACKAGE / name).read_text(encoding="utf-8")
        for target, section in re.findall(
            r"(IDEAL_FUNCTIONALITY\.md|LEAKAGE_ABUSE\.md)[^.\n]*?§(\d+)", text
        ):
            other = (PACKAGE / target).read_text(encoding="utf-8")
            assert re.search(rf"^##\s+{section}\.", other, re.MULTILINE), (
                f"{name} references {target} section {section}, which does not exist"
            )


def test_every_benchmark_is_classified_in_status():
    """A benchmark that is not classified can be quoted after being invalidated.

    Several results here were corrected by later measurement -- the cost model's
    MetaQA inputs, the volume-hiding shuffle estimate, the crossover's transfer
    to real data. STATUS.md records where each one stands, and this keeps that
    list complete so a new benchmark cannot be added without saying so.
    """

    status = (PACKAGE / "benchmarks" / "STATUS.md").read_text(encoding="utf-8")
    recorded = sorted(p.name for p in (PACKAGE / "benchmarks").glob("*.json"))
    missing = [name for name in recorded if name not in status]
    assert not missing, f"benchmarks absent from STATUS.md: {missing}"


def test_status_marks_the_invalidated_cost_model():
    """The one file whose numbers are known wrong must say so in both places."""

    import json

    status = (PACKAGE / "benchmarks" / "STATUS.md").read_text(encoding="utf-8")
    assert "Invalidated" in status
    assert "relation_page_cost_model.json" in status

    model = json.loads(
        (PACKAGE / "benchmarks" / "relation_page_cost_model.json").read_text()
    )
    assert "INVALIDATED" in model
    assert "4,176" in model["INVALIDATED"]["reason"] or "4176" in str(model["INVALIDATED"])
    assert model["scope_warning"].startswith("INVALIDATED")


def test_status_keeps_the_crossover_scoped_to_synthetic_data():
    """17.5x must never travel without the narrowing factor it was taken at."""

    status = (PACKAGE / "benchmarks" / "STATUS.md").read_text(encoding="utf-8")
    assert "17.5" in status
    assert "narrowing factor 8" in status
    assert "1.00" in status
    assert "does **not** transfer" in status or "does not transfer" in status


def test_superseded_benchmarks_are_listed_under_superseded():
    """A benchmark labelled superseded must not sit in the Stands table.

    This drift happened: two RAG benchmarks were annotated "(superseded by ...)"
    but left under Stands, so a reader scanning that table would have quoted
    40-question numbers that a 400-question run had already replaced. The
    presence check alone did not catch it, because they WERE listed.
    """

    import re

    text = (PACKAGE / "benchmarks" / "STATUS.md").read_text(encoding="utf-8")
    stands = text.split("## Stands")[1]
    offenders = re.findall(r"`([a-z_]+\.json)`[^\n|]*superseded", stands)
    assert not offenders, (
        f"marked superseded but listed under Stands: {offenders}"
    )


def test_status_header_count_matches_the_directory():
    """The header states how many benchmarks there are; it drifts as they grow."""

    words = {
        "Twenty-six": 26, "Twenty-seven": 27, "Twenty-eight": 28, "Twenty-nine": 29,
        "Thirty": 30, "Thirty-one": 31, "Thirty-two": 32, "Thirty-three": 33,
        "Thirty-four": 34, "Thirty-five": 35, "Thirty-six": 36,
        "Thirty-seven": 37, "Thirty-eight": 38, "Thirty-nine": 39,
        "Forty": 40, "Forty-one": 41, "Forty-two": 42, "Forty-three": 43,
        "Forty-four": 44, "Forty-five": 45, "Forty-six": 46,
        "Forty-seven": 47, "Forty-eight": 48,
    }
    text = (PACKAGE / "benchmarks" / "STATUS.md").read_text(encoding="utf-8")
    actual = len(list((PACKAGE / "benchmarks").glob("*.json")))
    stated = next((n for w, n in words.items() if text.startswith(f"# What each")
                   and f"{w} benchmarks" in text), None)
    assert stated == actual, (
        f"STATUS.md header says {stated} benchmarks, directory has {actual}"
    )


# --------------------------------------------------------------------------
# The new layouts shrink the TABLE, not the asymptotics
# --------------------------------------------------------------------------

NEW_LAYOUT_SOURCES = (
    PACKAGE / "compact_directory.py",
    PACKAGE / "type_blocked_directory.py",
    PACKAGE / "hybrid_directory.py",
    PACKAGE / "KG_VS_PLAIN_GRAPH.md",
)


@pytest.mark.parametrize("document", NEW_LAYOUT_SOURCES, ids=lambda p: p.name)
def test_new_layouts_never_claim_sublinearity(document: Path):
    """A smaller table is not a better asymptotic.

    The compact, type-blocked and hybrid layouts reduce the directory from
    O(entity_count * relation_count) to roughly O(keys). Every read still scans
    the whole table, so all of them are Theta(table). Calling that "sublinear"
    would be false and would also discard the project's one established
    differentiator: GORAM gets sublinear access from an ORAM under honest
    majority, and this design cannot, which is precisely the 261x premium.

    This guard exists because the claim was voiced out loud during development.
    """

    text = _normalized(document)
    for pattern, description in FORBIDDEN_CLAIMS:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        assert match is None, f"{document} {description}: {match.group(0)!r}"
    # Sublinearity may be DENIED, or ATTRIBUTED to a system that has it. What it
    # may not be is asserted about this design. Same shape as the
    # servers-learn-nothing guard: find every occurrence and require that its
    # context disowns it.
    lowered = text.lower()
    disowned = (
        "not ", "never ", "no ", "nothing ", "cannot ", "can not ", "without ",
        "rather than", "instead of", "would be false", "is not",
        # Giving it up is also a denial, not a claim.
        "losing ", "loses ", "lost ", "forgoes ", "gives up ", "closes off",
    )
    attributed = ("goram", "oram", "honest majority", "aby3", "dpf", "fss")
    start = 0
    while (found := lowered.find("sublinear", start)) != -1:
        window = lowered[max(0, found - 120):found + 40]
        assert any(mark in window for mark in disowned + attributed), (
            f"{document} uses 'sublinear' at offset {found} without denying it "
            f"or attributing it elsewhere: ...{text[max(0, found-90):found+60]}..."
        )
        start = found + len("sublinear")
    # polylog belongs only to systems that achieve it.
    start = 0
    while (found := lowered.find("polylog", start)) != -1:
        window = lowered[max(0, found - 120):found + 40]
        assert any(mark in window for mark in disowned + attributed), (
            f"{document} claims polylogarithmic access"
        )
        start = found + len("polylog")


def test_kg_document_states_the_asymptotics_and_the_goram_direction():
    """The comparison must not be left for a reader to guess the wrong way round.

    GORAM is an ORAM on an honest-majority backend, so it has the better
    asymptotics; this design's claim is the stronger corruption threshold. A
    document that omits that ordering invites exactly the inversion this guard
    was written after.
    """

    text = _normalized(PACKAGE / "KG_VS_PLAIN_GRAPH.md")
    assert "honest majority" in text.lower()
    assert "ABY3" in text
    # It must say, somewhere, that this design's reads are linear.
    assert re.search(r"linear", text, flags=re.IGNORECASE), (
        "the document must state that every read is a full linear scan"
    )
    # And it must not present the layout work as closing the asymptotic gap.
    assert "261" in text, (
        "the threat-model premium is the differentiator and must travel with "
        "the comparison"
    )
