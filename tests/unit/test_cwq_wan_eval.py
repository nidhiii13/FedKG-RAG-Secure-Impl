import json

import pytest

from scripts.run_cwq_wan_eval import PROFILES, summarize


def test_profiles_include_direct_and_zero_delay_controls():
    assert PROFILES["localhost"] is None
    assert PROFILES["proxy_control_0ms_1000mbps"] == (0.0, 1000.0)
    assert PROFILES["campus_2ms_1000mbps"] == (2.0, 1000.0)


def test_summary_reports_medians_exactness_and_control_ratios(tmp_path):
    runs = []
    for profile, values in {
        "localhost": [1.0, 1.2, 1.1],
        "proxy_control_0ms_1000mbps": [2.0, 2.2, 2.1],
        "campus_2ms_1000mbps": [6.0, 6.2, 6.1],
    }.items():
        for repetition, value in enumerate(values, 1):
            runs.append(
                {
                    "profile": profile,
                    "repetition": repetition,
                    "status": "completed",
                    "all_exact": True,
                    "mpc_seconds_per_query": value,
                    "global_mb_per_query": 198.6,
                    "wall_seconds": value * 10,
                }
            )
    result = summarize(tmp_path, runs)
    by_name = {item["profile"]: item for item in result["profiles"]}
    assert by_name["localhost"]["median_mpc_seconds_per_query"] == 1.1
    assert by_name["campus_2ms_1000mbps"][
        "mpc_slowdown_vs_zero_delay_proxy"
    ] == pytest.approx(6.1 / 2.1)
    assert by_name["campus_2ms_1000mbps"]["all_exact"] is True
    saved = json.loads((tmp_path / "summary.json").read_text())
    assert saved["real_wan_deployment"] is False
