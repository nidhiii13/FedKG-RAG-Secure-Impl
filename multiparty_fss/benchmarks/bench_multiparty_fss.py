#!/usr/bin/env python3
"""Benchmark the BGI15 p-party DPF prototype (and the legacy 2-party CLI).

Measures, per party count N and universe size U:
  keygen wall time, per-evaluator key size (raw and serialized JSON),
  total key material, scalar eval time, full-universe batch eval time,
  XOR combine time, and communication sizes (client->evaluator request,
  evaluator->combiner response).

The N=2 row, when the native two-party CLI binary is present, drives
tools/fss_cli/fedkg-fss-cli through the existing FssCliBackend for COMPARISON
ONLY: it is a different construction (BGI16-style tree DPF), a different
domain (2^64 vs rank domain), a different output group (Z_2^64 vs GF(2)^64),
and its timings include one subprocess spawn per CLI call. See
docs/benchmarks.md for methodology and caveats. Prototype numbers, not
production claims.

Usage:  .venv/bin/python multiparty_fss/benchmarks/bench_multiparty_fss.py \
            [--universe 4096] [--repeat 5] [--json out.json]
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import secrets

from multiparty_fss.combine import combine_vectors
from multiparty_fss.evaluate import evaluate, evaluate_universe
from multiparty_fss.keygen import generate
from multiparty_fss.params import MpDpfParams, domain_bits_for_universe, honest_majority_threshold
from multiparty_fss.requests import MpFssEvaluatorResponse


def _median_time(fn, repeat: int) -> float:
    samples = []
    for _ in range(repeat):
        start = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - start)
    return statistics.median(samples)


def bench_multiparty(party_count: int, universe: int, repeat: int) -> dict:
    domain_bits = domain_bits_for_universe(universe)
    threshold = honest_majority_threshold(party_count)
    params = MpDpfParams.create(domain_bits, party_count, threshold)
    alpha = secrets.randbelow(universe)
    beta = 1

    keygen_time = _median_time(
        lambda: generate(alpha, beta, party_count, threshold, params=params), repeat
    )
    shares = generate(alpha, beta, party_count, threshold, params=params)
    raw_key_bytes = len(shares[0].sigma) + len(shares[0].correction_words)
    serialized = json.dumps(shares[0].to_dict())
    serialized_bytes = len(serialized.encode("ascii"))

    scalar_point = universe // 2
    scalar_time = _median_time(
        lambda: evaluate(shares[0], scalar_point), max(repeat, 5)
    )
    batch_time = _median_time(
        lambda: evaluate_universe(shares[0], universe), max(1, repeat // 2)
    )

    vectors = {
        s.party_index: [int(v) for v in evaluate_universe(s, universe)] for s in shares
    }
    combine_time = _median_time(
        lambda: combine_vectors(vectors, party_count), repeat
    )
    combined = combine_vectors(vectors, party_count)
    assert combined[alpha] == beta and sum(combined) == beta  # sanity

    response = MpFssEvaluatorResponse(
        request_id="bench",
        evaluator_id="bench-eval",
        party_index=0,
        party_count=party_count,
        threshold=threshold,
        params_id=params.params_id(),
        keygen_id=shares[0].keygen_id,
        domain="entity",
        universe_digest="0" * 64,
        payload_kind="dense",
        point_count=universe,
        value_shares=tuple(vectors[0]),
        projection_digest=None,
        slot_handles=None,
        candidate_slot_shares=None,
    )
    response_bytes = len(json.dumps(response.to_dict()).encode("ascii"))

    return {
        "path": "multiparty",
        "construction": "bgi15-mpdpf-p0",
        "party_count": party_count,
        "threshold": threshold,
        "universe": universe,
        "domain_bits": domain_bits,
        "mu": params.mu,
        "nu": params.nu,
        "seeds_per_row": params.seeds_per_row,
        "keygen_s": keygen_time,
        "key_bytes_raw_per_evaluator": raw_key_bytes,
        "key_bytes_serialized_per_evaluator": serialized_bytes,
        "total_key_bytes_raw": raw_key_bytes * party_count,
        "scalar_eval_s": scalar_time,
        "batch_eval_universe_s": batch_time,
        "combine_universe_s": combine_time,
        "client_to_evaluator_bytes": serialized_bytes,
        "evaluator_to_combiner_bytes_dense": response_bytes,
    }


def bench_legacy_two_party(universe: int, repeat: int) -> dict | None:
    cli = ROOT / "build" / "fss_cli" / "fedkg-fss-cli"
    if not cli.exists():
        return None
    from src.crypto.fss_cli_backend import FssCliBackend

    backend = FssCliBackend.from_executable(cli)
    alpha_hex = secrets.token_hex(8)
    points = [format(i, "016x") for i in range(universe)]

    keygen_time = _median_time(
        lambda: backend.gen(alpha_hex, 1, ["e0", "e1"]), repeat
    )
    shares = backend.gen(alpha_hex, 1, ["e0", "e1"])
    serialized_bytes = len(json.dumps(shares["e0"].payload).encode("ascii"))
    scalar_time = _median_time(
        lambda: backend.eval(shares["e0"], points[0]), max(repeat, 5)
    )
    start = time.perf_counter()
    values = backend.eval_many(shares["e0"], points)
    batch_time = time.perf_counter() - start
    assert len(values) == universe

    return {
        "path": "legacy-two-party (comparison only)",
        "construction": "bgi16-tree-dpf (myl7/fss via subprocess CLI)",
        "party_count": 2,
        "threshold": "n/a (two-server non-collusion)",
        "universe": universe,
        "domain_bits": 64,
        "keygen_s": keygen_time,
        "key_bytes_serialized_per_evaluator": serialized_bytes,
        "total_key_bytes_serialized": serialized_bytes * 2,
        "scalar_eval_s": scalar_time,
        "batch_eval_universe_s": batch_time,
        "note": "timings include one subprocess spawn per CLI call (256-point batches)",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--universe", type=int, action="append", default=None)
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument("--skip-legacy", action="store_true")
    parser.add_argument("--json", type=Path, default=None)
    args = parser.parse_args()
    universes = args.universe or [4096]

    rows = []
    for universe in universes:
        for party_count in (3, 4, 5, 7, 8):
            row = bench_multiparty(party_count, universe, args.repeat)
            rows.append(row)
            print(
                f"N={party_count} t={row['threshold']} U={universe} "
                f"(n={row['domain_bits']}, mu={row['mu']}, nu={row['nu']}): "
                f"keygen {row['keygen_s']*1e3:.1f} ms, "
                f"key {row['key_bytes_raw_per_evaluator']/1024:.1f} KiB raw "
                f"({row['key_bytes_serialized_per_evaluator']/1024:.1f} KiB json), "
                f"scalar {row['scalar_eval_s']*1e3:.2f} ms, "
                f"universe eval {row['batch_eval_universe_s']*1e3:.1f} ms, "
                f"combine {row['combine_universe_s']*1e3:.1f} ms",
                flush=True,
            )
        if not args.skip_legacy:
            legacy = bench_legacy_two_party(universe, args.repeat)
            if legacy is not None:
                rows.append(legacy)
                print(
                    f"N=2 legacy CLI U={universe}: keygen {legacy['keygen_s']*1e3:.1f} ms, "
                    f"key {legacy['key_bytes_serialized_per_evaluator']/1024:.1f} KiB json, "
                    f"scalar {legacy['scalar_eval_s']*1e3:.2f} ms, "
                    f"universe eval {legacy['batch_eval_universe_s']:.2f} s "
                    f"({legacy['note']})",
                    flush=True,
                )
            else:
                print("N=2 legacy CLI not built; skipping comparison row", flush=True)
    if args.json:
        args.json.write_text(json.dumps(rows, indent=2))
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
