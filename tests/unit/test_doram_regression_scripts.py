import json
from pathlib import Path

from scripts.analyze_doram_regression import analyze_dataset, parse_party_zero_log
from scripts.run_doram_regression import (
    batch_is_complete,
    document_digest,
    repeated,
)


def write_party_zero_log(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            (
                "Time = 12.5 seconds ",
                "Time10 = 0.5 seconds (0 MB, 0 rounds, 0.5 CPU seconds)",
                "Time11 = 2 seconds (10 MB, 20 rounds, 3 CPU seconds)",
                "Time12 = 0.25 seconds (1 MB, 2 rounds, 0.3 CPU seconds)",
                "Time13 = 8 seconds (30 MB, 40 rounds, 9 CPU seconds)",
                "Time20 = 1 seconds (2 MB, 3 rounds, 1 CPU seconds)",
                "Time21 = 0.01 seconds (0.1 MB, 1 rounds, 0.01 CPU seconds)",
                "Time22 = 1.5 seconds (2 MB, 3 rounds, 1 CPU seconds)",
                "Time23 = 0.02 seconds (0.1 MB, 1 rounds, 0.01 CPU seconds)",
                "Data sent = 43.2 MB in ~69 rounds (party 0 only)",
                "Global data sent = 129.6 MB (all parties)",
            )
        )
        + "\n",
        encoding="utf-8",
    )


def test_repeated_queries_cycle_to_requested_count():
    values, indices = repeated([{"q": 0}, {"q": 1}, {"q": 2}], 8)
    assert indices == [0, 1, 2, 0, 1, 2, 0, 1]
    assert [row["q"] for row in values] == indices


def test_resume_batch_is_bound_to_program_queries_and_expected_results(
    tmp_path: Path,
):
    query_digest = document_digest([{"q": 1}])
    expected_digest = document_digest([[{"valid": 1}]])
    (tmp_path / "batch_summary.json").write_text(
        json.dumps(
            {
                "status": "completed",
                "all_outputs_match_bounded_reference": True,
                "program": "scan-v2",
                "program_source_digest": "source-v2",
                "query_digest": query_digest,
                "expected_digest": expected_digest,
            }
        )
    )
    (tmp_path / "decoded.json").write_text(json.dumps([[{"valid": 1}]]))
    assert batch_is_complete(
        tmp_path,
        1,
        "scan-v2",
        "source-v2",
        query_digest,
        expected_digest,
    )
    assert not batch_is_complete(
        tmp_path,
        1,
        "scan-v1",
        "source-v2",
        query_digest,
        expected_digest,
    )
    assert not batch_is_complete(
        tmp_path,
        1,
        "scan-v2",
        "source-v2",
        document_digest([{"q": 2}]),
        expected_digest,
    )


def test_parse_party_zero_log_sums_candidate_and_output_timers(tmp_path: Path):
    log = tmp_path / "server-0.log"
    write_party_zero_log(log)
    result = parse_party_zero_log(log)
    assert result["mpc_seconds"] == 12.5
    assert result["candidate_topk_seconds"] == 2.5
    assert result["output_reshare_seconds"] == 0.03
    assert result["global_data_mb"] == 129.6
    assert result["reported_rounds"] == 69


def test_analysis_separates_executions_from_distinct_queries(tmp_path: Path):
    (tmp_path / "run_manifest.json").write_text(
        json.dumps(
            {
                "dataset": "fixture",
                "scope": "repetition accounting test",
                "query_count": 3,
                "execution_count": 3,
                "distinct_query_count": 2,
                "unique_base_queries": 2,
                "batch_count": 0,
                "rounds_warning": "test",
            }
        )
    )
    (tmp_path / "queries.json").write_text(
        json.dumps([{"q": 0}, {"q": 1}, {"q": 0}])
    )
    (tmp_path / "expected.json").write_text(
        json.dumps([[{"valid": 1}], [{"valid": 0}], [{"valid": 1}]])
    )
    result = analyze_dataset(tmp_path)
    assert result["execution_count"] == 3
    assert result["distinct_query_count"] == 2
    assert "executions" in result["correctness_unit"]
    assert result["bounded_reference_match_rate"] is None


def test_analysis_recomputes_decoded_against_expected(tmp_path: Path):
    queries = [{"q": 0}]
    expected = [[{"valid": 1}]]
    decoded = [[{"valid": 0}]]
    (tmp_path / "run_manifest.json").write_text(
        json.dumps(
            {
                "dataset": "fixture",
                "scope": "tamper test",
                "reference_kind": "unit-test bounded reference",
                "query_count": 1,
                "execution_count": 1,
                "distinct_query_count": 1,
                "unique_base_queries": 1,
                "batch_size": 1,
                "batch_count": 1,
                "rounds_warning": "test",
            }
        )
    )
    (tmp_path / "queries.json").write_text(json.dumps(queries))
    (tmp_path / "expected.json").write_text(json.dumps(expected))
    batch_dir = tmp_path / "batch-000"
    batch_dir.mkdir()
    (batch_dir / "decoded.json").write_text(json.dumps(decoded))
    (batch_dir / "batch_summary.json").write_text(
        json.dumps(
            {
                "status": "completed",
                "global_query_start": 0,
                "query_count": 1,
                "query_digest": document_digest(queries),
                "expected_digest": document_digest(expected),
                "per_execution_reference_match": [True],
                "all_outputs_match_bounded_reference": True,
                "wall_seconds": 1.0,
            }
        )
    )
    write_party_zero_log(batch_dir / "logs" / "server-0.log")

    result = analyze_dataset(tmp_path)

    assert result["completed_executions"] == 1
    assert result["reference_matching_executions"] == 0
    assert result["bounded_reference_match_rate"] == 0.0
    assert result["all_mpc_outputs_match_bounded_reference"] is False
    assert result["integrity_errors"] == [
        f"{batch_dir}: reference-match vector mismatch",
        f"{batch_dir}: reference-match flag mismatch",
    ]


# --------------------------------------------------------------------------
# Backend selection
#
# The regression harness can drive either storage layout. What must hold is
# that the two layouts stay distinguishable in the recorded artifacts and that
# their independent cleartext oracles agree, since a cross-backend comparison
# of decoded results is only meaningful if both are checked separately.
# --------------------------------------------------------------------------


FIXTURE = Path("doram_t2_3pc/examples/ten_query")


def test_backend_rejects_unknown_keys():
    import pytest

    from scripts.run_doram_regression import Backend

    with pytest.raises(ValueError, match="unknown backend"):
        Backend("sublinear-doram")


def test_backends_select_distinct_layouts_and_programs():
    from scripts.run_doram_regression import Backend

    scan = Backend("packed-scan")
    paged = Backend("relation-paged")

    assert scan.paged is False and paged.paged is True
    assert scan.config_basename != paged.config_basename
    assert scan.owner_shard_prefix != paged.owner_shard_prefix
    # The experimental status has to travel into the run manifest.
    assert "EXPERIMENTAL" in paged.status
    assert "EXPERIMENTAL" not in scan.status

    scan_config = scan.load_config(FIXTURE / scan.config_basename)
    paged_config = paged.load_config(FIXTURE / paged.config_basename)
    assert scan.program_name(scan_config, 2).startswith("doram_scan_3pc_")
    assert paged.program_name(paged_config, 2).startswith("paged_kg_3pc_")


def test_both_backends_share_one_client_facing_public_config():
    """Query shards and decoding are backend-independent; only storage differs."""

    from scripts.run_doram_regression import Backend

    scan = Backend("packed-scan")
    paged = Backend("relation-paged")
    scan_base = scan.base_config(scan.load_config(FIXTURE / scan.config_basename))
    paged_base = paged.base_config(paged.load_config(FIXTURE / paged.config_basename))

    assert scan_base.owners == paged_base.owners
    assert scan_base.entities == paged_base.entities
    assert scan_base.relations == paged_base.relations
    assert scan_base.top_k == paged_base.top_k
    assert scan_base.field_prime == paged_base.field_prime


def test_independent_oracles_agree_across_backends():
    """The two layouts must answer every fixture query identically."""

    from scripts.run_doram_regression import Backend

    scan = Backend("packed-scan")
    paged = Backend("relation-paged")
    scan_config = scan.load_config(FIXTURE / scan.config_basename)
    paged_config = paged.load_config(FIXTURE / paged.config_basename)
    owner_edges = {
        owner: json.loads((FIXTURE / f"{owner}.json").read_text())
        for owner in scan.base_config(scan_config).owners
    }
    queries = json.loads((FIXTURE / "queries.json").read_text())
    assert queries

    for query in queries:
        assert scan.evaluate_cleartext(
            scan_config, owner_edges, query
        ) == paged.evaluate_cleartext(paged_config, owner_edges, query)
