#!/usr/bin/env python3
"""Master paper-level evaluation driver.

Phases (each can be skipped via flags):
  1. microbench — construction-level sweep over universe sizes and party
     counts, against baselines implemented in the same language and PRG
     family: BGI15 p-party grid DPF (this work's path, N in {3,5,7}), the
     standard two-party tree DPF (baseline; two-server non-collusion model),
     and naive (N-1)-private truth-table XOR sharing. Metrics per point:
     keygen time, per-evaluator key bytes, scalar eval, full-universe eval —
     median and IQR over repetitions after a warm-up rep.
  2. datasets — the end-to-end dataset harness (eval_datasets.py) over
     MetaQA (real 2-party federation), WebQSP (real 5-party federation),
     LC-QuAD 2.0, KQA Pro, CWQ (closure + RoG), plus MetaQA N=5/7 scaling;
     in-process transport, --repeats timing repetitions.
  3. socket — deployed-mode reruns (real process-separated evaluators over
     localhost TCP with full JSON marshaling) for MetaQA and KQA Pro.
  4. report artifacts — CSV tables and dependency-free SVG figures written
     to multiparty_fss/benchmarks/paper_results/ (stores and bulky per-query
     dumps stay under --work).

Usage:
  .venv/bin/python multiparty_fss/benchmarks/paper_eval.py \
      --work /tmp/mpfss_paper --queries 50 --repeats 3
"""

from __future__ import annotations

import argparse
import csv
import json
import platform
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import secrets

import numpy as np

from multiparty_fss.baselines import NaiveXorSharing, TreeDpf2Party
from multiparty_fss.combine import combine
from multiparty_fss.evaluate import evaluate, evaluate_universe
from multiparty_fss.keygen import generate
from multiparty_fss.params import MpDpfParams, honest_majority_threshold

RESULTS_DIR = ROOT / "multiparty_fss" / "benchmarks" / "paper_results"

UNIVERSE_SWEEP = [1 << 10, 1 << 12, 1 << 14, 1 << 16, 1 << 18, 1 << 20]
MPDPF_PARTY_COUNTS = [3, 5, 7]
TREE_EVALFULL_CAP = 1 << 18  # level-order list memory/time cap in Python
NAIVE_CAP = 1 << 20


def _timed(fn, reps: int) -> tuple[float, float]:
    """(median_ms, iqr_ms) over `reps` runs after one warm-up run."""
    fn()
    samples = []
    for _ in range(reps):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1e3)
    samples.sort()
    median = statistics.median(samples)
    iqr = (
        samples[(3 * len(samples)) // 4] - samples[len(samples) // 4]
        if len(samples) >= 4
        else samples[-1] - samples[0]
    )
    return median, iqr


def bench_mpdpf(universe: int, party_count: int, reps: int) -> dict:
    domain_bits = max(universe - 1, 1).bit_length()
    threshold = honest_majority_threshold(party_count)
    params = MpDpfParams.create(domain_bits, party_count, threshold)
    alpha = secrets.randbelow(universe)

    keygen_ms, keygen_iqr = _timed(
        lambda: generate(alpha, 1, party_count, threshold, params=params), reps
    )
    shares = generate(alpha, 1, party_count, threshold, params=params)
    scalar_ms, scalar_iqr = _timed(
        lambda: evaluate(shares[0], universe // 2), max(reps, 5)
    )
    evalfull_ms, evalfull_iqr = _timed(
        lambda: evaluate_universe(shares[0], universe), max(2, reps // 2)
    )
    # correctness spot check on this exact instance
    assert (
        combine({s.party_index: evaluate(s, alpha) for s in shares}, party_count) == 1
    )
    return {
        "construction": f"mpdpf-N{party_count}",
        "model": f"honest-majority t={threshold}",
        "universe": universe,
        "domain_bits": domain_bits,
        "keygen_ms": keygen_ms,
        "keygen_iqr_ms": keygen_iqr,
        "key_bytes_per_evaluator": len(shares[0].sigma) + len(shares[0].correction_words),
        "total_key_bytes": party_count
        * (len(shares[0].sigma) + len(shares[0].correction_words)),
        "scalar_ms": scalar_ms,
        "scalar_iqr_ms": scalar_iqr,
        "evalfull_ms": evalfull_ms,
        "evalfull_iqr_ms": evalfull_iqr,
    }


def bench_tree(universe: int, reps: int) -> dict:
    domain_bits = max(universe - 1, 1).bit_length()
    dpf = TreeDpf2Party(domain_bits)
    alpha = secrets.randbelow(universe)
    keygen_ms, keygen_iqr = _timed(lambda: dpf.generate(alpha, 1), reps)
    key0, key1 = dpf.generate(alpha, 1)
    scalar_ms, scalar_iqr = _timed(
        lambda: dpf.evaluate(key0, universe // 2), max(reps, 5)
    )
    if universe <= TREE_EVALFULL_CAP:
        evalfull_ms, evalfull_iqr = _timed(
            lambda: dpf.evaluate_full(key0, universe), 2
        )
    else:
        evalfull_ms = evalfull_iqr = None
    assert dpf.combine(dpf.evaluate(key0, alpha), dpf.evaluate(key1, alpha)) == 1
    return {
        "construction": "tree-dpf-2party",
        "model": "two-server non-collusion (baseline only)",
        "universe": universe,
        "domain_bits": domain_bits,
        "keygen_ms": keygen_ms,
        "keygen_iqr_ms": keygen_iqr,
        "key_bytes_per_evaluator": key0.key_bytes,
        "total_key_bytes": 2 * key0.key_bytes,
        "scalar_ms": scalar_ms,
        "scalar_iqr_ms": scalar_iqr,
        "evalfull_ms": evalfull_ms,
        "evalfull_iqr_ms": evalfull_iqr,
    }


def bench_naive(universe: int, party_count: int, reps: int) -> dict | None:
    if universe > NAIVE_CAP:
        return None
    domain_bits = max(universe - 1, 1).bit_length()
    naive = NaiveXorSharing(domain_bits, party_count)
    alpha = secrets.randbelow(universe)
    keygen_ms, keygen_iqr = _timed(lambda: naive.generate(alpha, 1), max(2, reps // 2))
    keys = naive.generate(alpha, 1)
    scalar_ms, scalar_iqr = _timed(
        lambda: NaiveXorSharing.evaluate(keys[0], universe // 2), max(reps, 5)
    )
    evalfull_ms, evalfull_iqr = _timed(
        lambda: NaiveXorSharing.evaluate_full(keys[0], universe), max(2, reps // 2)
    )
    return {
        "construction": f"naive-xor-N{party_count}",
        "model": f"(N-1)-private, information-theoretic",
        "universe": universe,
        "domain_bits": domain_bits,
        "keygen_ms": keygen_ms,
        "keygen_iqr_ms": keygen_iqr,
        "key_bytes_per_evaluator": keys[0].key_bytes,
        "total_key_bytes": party_count * keys[0].key_bytes,
        "scalar_ms": scalar_ms,
        "scalar_iqr_ms": scalar_iqr,
        "evalfull_ms": evalfull_ms,
        "evalfull_iqr_ms": evalfull_iqr,
    }


def run_microbench(reps: int) -> list[dict]:
    rows: list[dict] = []
    for universe in UNIVERSE_SWEEP:
        for party_count in MPDPF_PARTY_COUNTS:
            rows.append(bench_mpdpf(universe, party_count, reps))
            print(
                f"  microbench mpdpf N={party_count} U=2^{rows[-1]['domain_bits']} "
                f"key={rows[-1]['key_bytes_per_evaluator']/1024:.0f}KiB "
                f"evalfull={rows[-1]['evalfull_ms']:.1f}ms",
                flush=True,
            )
        rows.append(bench_tree(universe, reps))
        naive_row = bench_naive(universe, 3, reps)
        if naive_row:
            rows.append(naive_row)
    return rows


def write_csv(rows: list[dict], path: Path) -> None:
    fields = list(rows[0].keys())
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def emit_figures(rows: list[dict]) -> None:
    from multiparty_fss.benchmarks.svgplot import line_chart

    def series_for(metric: str, constructions: list[str]) -> list[dict]:
        out = []
        for name in constructions:
            pts = sorted(
                (r["universe"], r[metric])
                for r in rows
                if r["construction"] == name and r[metric] is not None
            )
            out.append(
                {"name": name, "xs": [p[0] for p in pts], "ys": [p[1] for p in pts]}
            )
        return out

    constructions = [
        "mpdpf-N3",
        "mpdpf-N5",
        "mpdpf-N7",
        "tree-dpf-2party",
        "naive-xor-N3",
    ]
    line_chart(
        series_for("key_bytes_per_evaluator", constructions),
        RESULTS_DIR / "fig_key_size_vs_universe.svg",
        "Per-evaluator key size vs universe size",
        "universe size (points)",
        "key bytes / evaluator",
    )
    line_chart(
        series_for("evalfull_ms", constructions),
        RESULTS_DIR / "fig_evalfull_vs_universe.svg",
        "Full-universe evaluation time vs universe size (Python, 1 core)",
        "universe size (points)",
        "full-universe eval (ms)",
    )
    line_chart(
        series_for("scalar_ms", constructions),
        RESULTS_DIR / "fig_scalar_vs_universe.svg",
        "Single-point evaluation time vs universe size (Python, 1 core)",
        "universe size (points)",
        "scalar eval (ms)",
    )
    line_chart(
        series_for("keygen_ms", constructions),
        RESULTS_DIR / "fig_keygen_vs_universe.svg",
        "Key generation time vs universe size (Python, 1 core)",
        "universe size (points)",
        "keygen (ms)",
    )


def run_dataset_phase(work: Path, queries: int, repeats: int, transport: str, datasets: list[str], scaling: bool) -> None:
    argv = [
        sys.executable,
        str(ROOT / "multiparty_fss/benchmarks/eval_datasets.py"),
        "--queries",
        str(queries),
        "--party-count",
        "3",
        "--repeats",
        str(repeats),
        "--transport",
        transport,
        "--out",
        str(work / f"datasets_{transport}"),
    ]
    for dataset in datasets:
        argv += ["--dataset", dataset]
    if scaling:
        argv.append("--scaling")
    print(f"[datasets:{transport}] {' '.join(datasets)}", flush=True)
    completed = subprocess.run(argv, cwd=ROOT, text=True, capture_output=True)
    (work / f"datasets_{transport}.log").write_text(
        completed.stdout + "\n--- stderr ---\n" + completed.stderr
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"dataset phase ({transport}) failed; see "
            f"{work / f'datasets_{transport}.log'}"
        )
    # copy compact artifacts into the repo results dir
    src = work / f"datasets_{transport}"
    for path in src.glob("*_summary.json"):
        (RESULTS_DIR / path.name.replace("_summary", f"_{transport}_summary")).write_text(
            path.read_text()
        )
    summaries = src / f"all_summaries_{transport}.json"
    if summaries.exists():
        (RESULTS_DIR / summaries.name).write_text(summaries.read_text())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--queries", type=int, default=50)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--microbench-reps", type=int, default=5)
    parser.add_argument("--skip-microbench", action="store_true")
    parser.add_argument("--skip-datasets", action="store_true")
    parser.add_argument("--skip-socket", action="store_true")
    args = parser.parse_args()
    args.work.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    manifest = {
        "date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "python": platform.python_version(),
        "numpy": np.__version__,
        "cpu": "Intel Xeon Gold 6136 @ 3.00GHz (48 cores; single core used unless stated)",
        "queries_per_dataset": args.queries,
        "timing_repeats": args.repeats,
        "microbench_reps": args.microbench_reps,
    }

    if not args.skip_microbench:
        print("[microbench] sweep starting", flush=True)
        rows = run_microbench(args.microbench_reps)
        write_csv(rows, RESULTS_DIR / "microbench_constructions.csv")
        (RESULTS_DIR / "microbench_constructions.json").write_text(
            json.dumps(rows, indent=1)
        )
        emit_figures(rows)
        print("[microbench] done", flush=True)

    if not args.skip_datasets:
        run_dataset_phase(
            args.work,
            args.queries,
            args.repeats,
            "inprocess",
            ["metaqa", "webqsp", "lcquad2", "kqapro", "cwq"],
            scaling=True,
        )
    if not args.skip_socket:
        run_dataset_phase(
            args.work, args.queries, 1, "socket", ["metaqa", "kqapro"], scaling=False
        )

    (RESULTS_DIR / "run_manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"paper artifacts written to {RESULTS_DIR}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
