#!/usr/bin/env python3
"""Fail-closed verification of the CWQ numbers quoted in the thesis report."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FILES = {
    "compatibility": ROOT / "data/cwq/compatibility_summary.json",
    "capacity": ROOT / "data/cwq/full_union_capacity.json",
    "cleartext": ROOT / "results/cwq_cleartext_full1267_b8_k32_c50_20260827T093228Z/summary.json",
    "answers": ROOT / "results/cwq_cleartext_full1267_b8_k32_c50_20260827T093228Z/answers_a300.summary.json",
    "mpc_q10": ROOT / "results/cwq_mpc_temi_q10c3_20260827T100757Z/summary.json",
    "mpc_q25": ROOT / "results/cwq_mpc_temi_q25c3_20260827T102849Z/summary.json",
    "wan": ROOT / "results/cwq_wan_temi_q10_20260827T223000Z/summary.json",
    "ablations": ROOT / "results/cwq_runs_table.json",
    "per_question": ROOT / "results/cwq_cleartext_full1267_b8_k32_c50_20260827T093228Z/per_question.jsonl",
}


def load(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    missing = [str(path) for path in FILES.values() if not path.is_file()]
    require(not missing, f"missing report artifact(s): {missing}")

    compatibility = load(FILES["compatibility"])
    capacity = load(FILES["capacity"])
    cleartext = load(FILES["cleartext"])
    answers = load(FILES["answers"])
    q10 = load(FILES["mpc_q10"])
    q25 = load(FILES["mpc_q25"])
    wan = load(FILES["wan"])
    ablations = load(FILES["ablations"])
    per_question = load_jsonl(FILES["per_question"])

    require(compatibility["questions_total"] == 7050, "CWQ profile total changed")
    require(compatibility["strict_two_hop_compatible"] == 1267, "compatible count changed")
    require(sum(row["questions_total"] for row in compatibility["splits"]) == 7050,
            "split totals do not reconcile")
    require(sum(row["strict_two_hop_compatible"] for row in compatibility["splits"]) == 1267,
            "compatible split totals do not reconcile")
    categories: dict[str, int] = {}
    for split in compatibility["splits"]:
        require(sum(split["categories"].values()) == split["questions_total"],
                f"compatibility categories do not partition {split['split']}")
        for name, count in split["categories"].items():
            categories[name] = categories.get(name, 0) + count
    require(categories["multi_anchor_join_3_triples"] == 1096 and
            categories["chain_or_tree_3_triples"] == 1061 and
            categories["order_limit_or_temporal"] == 842 and
            categories["two_triples_not_dependent_chain"] == 805,
            "reported compatibility-category totals changed")

    require(capacity["entities"] == 1_055_994, "full-union entity count changed")
    require(capacity["unique_forward_edges"] == 3_447_420, "full-union edge count changed")
    require(capacity["relations"] == 5_689 and capacity["distinct_source_relation_keys"] == 2_019_811,
            "full-union relation/key counts changed")
    require(capacity["max_key_fanout"] == 429 and capacity["p99_key_fanout"] == 14,
            "full-union fanout statistics changed")
    require(cleartext["unique_ids"] == 1267 and cleartext["duplicate_ids"] == 0,
            "cleartext workload is not 1,267 unique questions")
    require(cleartext["evidence_hits"] == 1184, "primary evidence-hit count changed")
    require(cleartext["empty_retrievals"] == 79, "primary empty count changed")
    require((cleartext["bound"], cleartext["top_k"], cleartext["neighbourhood_cap"]) == (8, 32, 50),
            "primary public bounds changed")
    require((cleartext["fixed_union_entities"], cleartext["fixed_union_unique_forward_edges"],
             cleartext["fixed_union_directed_records_incl_inverses"]) == (293_028, 854_421, 1_708_842),
            "selected-union capacity changed")
    fixture = cleartext["fixture"]
    require((fixture["entities"], fixture["relations"], fixture["directory_rows"]) ==
            (75_611, 5_203, 393_404_033), "primary fixture dimensions changed")
    require((fixture["edges_available"], fixture["edges_kept"]) == (634_946, 472_793),
            "primary fixture edge counts changed")
    require(fixture["owner_edge_counts"] == {
        "owner_0": 161_258, "owner_1": 154_035, "owner_2": 157_500
    }, "primary owner edge counts changed")
    require(cleartext["paged_vs_plaintext_same_bound_points"] == 0,
            "paged oracle no longer matches same-bound plaintext")
    require(cleartext["results_are_mpc"] is False, "cleartext run mislabeled as MPC")
    require(abs(cleartext["retrieval_seconds_per_query"] - 0.0009007835915075481) < 1e-15,
            "primary retrieval timing changed")
    require(len(per_question) == 1267 and len({row["id"] for row in per_question}) == 1267,
            "per-question output is incomplete or duplicated")
    split_results = {
        name: {
            "questions": sum(row["split"] == name for row in per_question),
            "hits": sum(row["split"] == name and row["hit"] for row in per_question),
        }
        for name in ("test", "validation")
    }
    require(split_results == {
        "test": {"questions": 664, "hits": 613},
        "validation": {"questions": 603, "hits": 571},
    }, "reported split-level retrieval results changed")

    require(answers["answers_scored"] == 300 and answers["answer_errors"] == 0,
            "generation sample/count changed")
    require(answers["overall_correct"] == 233, "generation correct count changed")
    require(answers["retrieval_hits_in_sample"] == 270, "generation retrieval-hit count changed")
    require(answers["retrieval_misses_included_not_dropped"] is True,
            "generation evaluation excluded retrieval misses")

    for label, run, expected_queries in (("q10", q10, 10), ("q25", q25, 25)):
        require(run["queries"] == expected_queries, f"{label} query count changed")
        require(run["all_exact"] is True, f"{label} is not exact")
        require(all(batch["exact_oracle_match"] for batch in run["batches"]),
                f"{label} contains an inexact batch")
        require(sum(batch["fields_compared"] for batch in run["batches"]) == 16 * expected_queries,
                f"{label} field count does not equal 4kQ with k=4")
    require(abs(q10["amortized_mpc_seconds_per_query"] - 2.04478) < 1e-9 and
            abs(q10["amortized_global_mb_per_query"] - 198.5998) < 1e-9,
            "q10 amortized cost changed")
    require(abs(q25["amortized_mpc_seconds_per_query"] - 3.377736) < 1e-9 and
            abs(q25["amortized_global_mb_per_query"] - 626.626) < 1e-9,
            "q25 amortized cost changed")

    require(len(wan["runs"]) == 12, "WAN run count changed")
    require(all(run["status"] == "completed" and run["all_exact"] for run in wan["runs"]),
            "WAN experiment has a failed or inexact repetition")
    require(sum(run["queries"] for run in wan["runs"]) == 120,
            "WAN query-execution count changed")
    require({row["profile"] for row in wan["profiles"]} == {
        "localhost", "proxy_control_0ms_1000mbps", "campus_2ms_1000mbps",
        "regional_20ms_100mbps"
    }, "WAN profile set changed")
    profile = {row["profile"]: row for row in wan["profiles"]}
    expected_medians = {
        "localhost": 1.822033,
        "proxy_control_0ms_1000mbps": 2.86259,
        "campus_2ms_1000mbps": 8.52144,
        "regional_20ms_100mbps": 48.9464,
    }
    require(all(abs(profile[name]["median_mpc_seconds_per_query"] - value) < 1e-9
                for name, value in expected_medians.items()), "WAN median changed")

    full_runs = [row for row in ablations if row["questions"] == 1267]
    require(len(full_runs) == 15, "full-workload ablation count changed")
    by_run = {row["run"]: row for row in full_runs}
    require(by_run["cwq_cleartext_full1267_b3_k32_c50_o3_subj_20260827T093858Z"]["hit_rate"] == 0.9305,
            "B=3 ablation changed")
    require(by_run["cwq_cleartext_full1267_b16_k32_c50_o3_subj_20260827T094326Z"]["hit_rate"] == 0.9361,
            "B=16 ablation changed")
    require(by_run["cwq_cleartext_full1267_b8_k4_c50_o3_subj_20260827T094829Z"]["hit_rate"] == 0.9337,
            "k=4 ablation changed")

    output = {
        "status": "verified",
        "facts": {
            "profiled_questions": 7050,
            "compatible_questions": 1267,
            "primary_evidence_hits": 1184,
            "primary_evidence_hit_rate": cleartext["evidence_hit_rate"],
            "generation_correct": answers["overall_correct"],
            "generation_scored": answers["answers_scored"],
            "mpc_fields_exact": sum(
                batch["fields_compared"] for run in (q10, q25) for batch in run["batches"]
            ),
            "wan_query_executions_exact": sum(run["queries"] for run in wan["runs"]),
        },
        "sha256": {name: sha256(path) for name, path in FILES.items()},
    }
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
