import json
from pathlib import Path

from scripts.analyze_doram_regression import parse_party_zero_log
from scripts.run_doram_regression import repeated


def test_repeated_queries_cycle_to_requested_count():
    values, indices = repeated([{"q": 0}, {"q": 1}, {"q": 2}], 8)
    assert indices == [0, 1, 2, 0, 1, 2, 0, 1]
    assert [row["q"] for row in values] == indices


def test_parse_party_zero_log_sums_candidate_and_output_timers(tmp_path: Path):
    log = tmp_path / "server-0.log"
    log.write_text(
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
        + "\n"
    )
    result = parse_party_zero_log(log)
    assert result["mpc_seconds"] == 12.5
    assert result["candidate_topk_seconds"] == 2.5
    assert result["output_reshare_seconds"] == 0.03
    assert result["global_data_mb"] == 129.6
    assert result["reported_rounds"] == 69
