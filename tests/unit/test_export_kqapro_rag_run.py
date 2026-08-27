import pytest

from scripts.export_kqapro_rag_run import checked_path, wilson


def test_checked_path_resolves_two_hop_evidence():
    edges = {
        11: {"source": "Q1", "relation": "r1", "target": "Q2"},
        12: {"source": "Q2", "relation": "r2", "target": "Q3"},
    }
    result = checked_path(
        {"left_evidence": 11, "right_evidence": 12, "score": 2},
        {"source": "Q1", "relation_1": "r1", "relation_2": "r2"},
        {"Q3"},
        edges,
        {"Q1": "one", "Q2": "two", "Q3": "three"},
    )
    assert result["edges"] == [["one", "r1", "two"], ["two", "r2", "three"]]
    assert result["evidence_handles"] == [11, 12]


def test_checked_path_rejects_disconnected_handles():
    edges = {
        11: {"source": "Q1", "relation": "r1", "target": "Q2"},
        12: {"source": "Q9", "relation": "r2", "target": "Q3"},
    }
    with pytest.raises(ValueError, match="do not form"):
        checked_path(
            {"left_evidence": 11, "right_evidence": 12, "score": 2},
            {"source": "Q1", "relation_1": "r1", "relation_2": "r2"},
            {"Q3"},
            edges,
            {},
        )


def test_wilson_all_successes_has_nontrivial_small_sample_interval():
    low, high = wilson(21, 21)
    assert 0.84 < low < 0.85
    assert high == pytest.approx(1.0)
