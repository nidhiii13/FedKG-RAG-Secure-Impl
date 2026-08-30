#!/usr/bin/env python3
"""Run distinct one-query trials against an existing relation-paged MPC epoch.

This harness is intended for large fixtures where compiling a multi-query
circuit would confound query latency with compiler growth.  Owner shares are
prepared once for a fixed epoch; every trial creates fresh query shares,
assembles a fresh private input stream, executes the same one-query circuit,
and checks all reconstructed fields against the independent cleartext oracle.
Only logs and compact verification records are retained in the output folder.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from doram_t2_3pc.decode_batch import decode_batch_logs  # noqa: E402
from doram_t2_3pc.io import read_json  # noqa: E402
from doram_t2_3pc.packed import create_packed_query_batch_shards  # noqa: E402
from doram_t2_3pc.packed import unpack_edge  # noqa: E402
from doram_t2_3pc.paged_shares import assemble_paged_batch_from_paths  # noqa: E402
from doram_t2_3pc.relation_pages import (  # noqa: E402
    RelationPageConfig,
    evaluate_paged_cleartext,
)
from doram_t2_3pc.run_pages_mpspdz import run as run_mpspdz  # noqa: E402
from scripts.analyze_doram_regression import parse_party_zero_log  # noqa: E402


DEFAULT_MPSPDZ = ROOT.parent / "SimGRAG" / "external" / "MP-SPDZ"


def write_json(path: Path, value: Any, *, private: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    os.chmod(path, 0o600 if private else 0o644)


def owner_server_shards(directories: list[Path]) -> list[list[Path]]:
    """Resolve one shard per server from each owner directory, in owner order."""

    resolved: list[list[Path]] = []
    for directory in directories:
        shards = []
        for server in range(3):
            matches = sorted(directory.glob(f"*to-server-{server}.json"))
            if len(matches) != 1:
                raise ValueError(
                    f"expected one server-{server} shard in {directory}, found {len(matches)}"
                )
            shards.append(matches[0].resolve())
        resolved.append(shards)
    return resolved


def load_owner_edges(
    config: RelationPageConfig,
    edge_config: RelationPageConfig,
    paths: list[Path],
    recovered: dict[int, tuple[int, int, int]] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Load oracle edges, translating public labels through numeric IDs.

    Historical benchmark fixtures sometimes use different textual labels for
    the same public entity namespace (for example ``e1`` and ``e000000`` both
    encode entity ID 1).  Translation by the explicit public maps avoids
    coupling verification to either spelling.
    """

    if len(paths) != len(config.base.owners):
        raise ValueError("--owner-edges must occur once per configured owner")
    entity_by_id = {value: key for key, value in config.base.entities.items()}
    relation_by_id = {value: key for key, value in config.base.relations.items()}
    result: dict[str, list[dict[str, Any]]] = {}
    for owner, path in zip(config.base.owners, paths, strict=True):
        value = read_json(path)
        if not isinstance(value, list):
            raise ValueError(f"owner edge file must contain a JSON list: {path}")
        translated = []
        for edge in value:
            if not isinstance(edge, dict):
                raise ValueError(f"owner edge file contains a non-object row: {path}")
            try:
                target_id = edge_config.base.entities[edge["target"]]
                relation_id = edge_config.base.relations[edge["relation"]]
                score = edge["score"]
                if recovered is not None:
                    target_id, relation_id, score = recovered[edge["evidence"]]
                translated.append({
                    **edge,
                    "source": entity_by_id[edge_config.base.entities[edge["source"]]],
                    "relation": relation_by_id[relation_id],
                    "target": entity_by_id[target_id],
                    "score": score,
                })
            except KeyError as exc:
                raise ValueError(
                    f"oracle edge namespace is incompatible with the execution config: {path}"
                ) from exc
        result[owner] = translated
    return result


def recover_page_edge_fields(
    config: RelationPageConfig, shard_matrix: list[list[Path]]
) -> dict[int, tuple[int, int, int]]:
    """Reconstruct evaluation-only target/relation/score fields from 3 shares.

    This is only appropriate in the centralized benchmark environment, which
    already creates all owner shares and verifies outputs.  It is never part of
    deployment query processing.  Evidence handles provide the stable join to
    the separately retained clear fixture.
    """

    recovered: dict[int, tuple[int, int, int]] = {}
    modulus = config.base.field_prime
    for owner_shards in shard_matrix:
        documents = [read_json(path) for path in owner_shards]
        page_vectors = [document.get("pages") for document in documents]
        if any(not isinstance(vector, list) for vector in page_vectors):
            raise ValueError("owner shard is missing its page vector")
        for shares in zip(*page_vectors, strict=True):
            packed = sum(shares) % modulus
            if packed == 0:
                continue
            target, relation, evidence, score, valid = unpack_edge(config.base, packed)
            if valid != 1 or evidence <= 0 or evidence in recovered:
                raise ValueError("reconstructed owner page contains an invalid or duplicate record")
            recovered[evidence] = (target, relation, score)
    return recovered


def aggregate(trials: list[dict[str, Any]]) -> dict[str, Any]:
    times = [float(trial["mpc_seconds_including_preprocessing"]) for trial in trials]
    traffic = [float(trial["global_data_mb"]) for trial in trials]
    return {
        "trials": len(trials),
        "exact_trials": sum(bool(trial["exact_oracle_match"]) for trial in trials),
        "mpc_seconds": {
            "median": statistics.median(times),
            "mean": statistics.fmean(times),
            "minimum": min(times),
            "maximum": max(times),
            "sample_stdev": statistics.stdev(times) if len(times) > 1 else 0.0,
        },
        "global_data_mb": {
            "median": statistics.median(traffic),
            "minimum": min(traffic),
            "maximum": max(traffic),
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument(
        "--owner-edge-config",
        type=Path,
        help="Public config describing labels in --owner-edges (defaults to --config)",
    )
    parser.add_argument("--owner-shard-dir", action="append", required=True, type=Path)
    parser.add_argument("--owner-edges", action="append", required=True, type=Path)
    parser.add_argument("--source", action="append", required=True)
    parser.add_argument(
        "--recover-edge-fields-from-owner-shards",
        action="store_true",
        help=(
            "Evaluation only: combine all three owner page shares to recover the "
            "exact target/relation/score fields when the original clear fixture differs"
        ),
    )
    parser.add_argument("--relation-one", default="r1")
    parser.add_argument("--relation-two", default="r2")
    parser.add_argument("--protocol", default="temi")
    parser.add_argument("--mpspdz-home", type=Path, default=DEFAULT_MPSPDZ)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--compile-timeout", type=int, default=1800)
    parser.add_argument("--runtime-timeout", type=int, default=3600)
    args = parser.parse_args()
    args.config = args.config.resolve()
    args.owner_edge_config = (
        args.owner_edge_config.resolve() if args.owner_edge_config else args.config
    )
    args.owner_shard_dir = [path.resolve() for path in args.owner_shard_dir]
    args.owner_edges = [path.resolve() for path in args.owner_edges]
    args.mpspdz_home = args.mpspdz_home.resolve()
    args.output_dir = args.output_dir.resolve()
    if len(set(args.source)) != len(args.source):
        parser.error("--source values must be distinct")
    return args


def main() -> int:
    args = parse_args()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise SystemExit(f"output directory is not empty: {args.output_dir}")
    args.output_dir.mkdir(parents=True, exist_ok=True)

    config = RelationPageConfig.load(args.config)
    edge_config = RelationPageConfig.load(args.owner_edge_config)
    if len(args.owner_shard_dir) != len(config.base.owners):
        raise ValueError("--owner-shard-dir must occur once per configured owner")
    shard_matrix = owner_server_shards(args.owner_shard_dir)
    recovered = (
        recover_page_edge_fields(config, shard_matrix)
        if args.recover_edge_fields_from_owner_shards
        else None
    )
    owner_edges = load_owner_edges(config, edge_config, args.owner_edges, recovered)
    queries = [
        {
            "source": source,
            "relation_1": args.relation_one,
            "relation_2": args.relation_two,
        }
        for source in args.source
    ]
    trials: list[dict[str, Any]] = []

    for index, query in enumerate(queries, start=1):
        trial_dir = args.output_dir / f"trial-{index:02d}"
        logs_dir = trial_dir / "logs"
        query_path = trial_dir / "query.json"
        write_json(query_path, [query], private=True)
        expected = [evaluate_paged_cleartext(config, owner_edges, query)]

        with tempfile.TemporaryDirectory(prefix="fedkg-large-query-", dir="/tmp") as temporary:
            work = Path(temporary)
            query_shards = create_packed_query_batch_shards(
                config.base, query_path, work / "query-shards"
            )
            instance = work / "instance"
            started = time.perf_counter()
            for server in range(3):
                assemble_paged_batch_from_paths(
                    config,
                    server,
                    1,
                    query_shards[server],
                    [owner_shards[server] for owner_shards in shard_matrix],
                    instance / f"Input-P{server}-0",
                )
            assembly_seconds = time.perf_counter() - started
            input_bytes = sum(
                (instance / f"Input-P{server}-0").stat().st_size for server in range(3)
            )

            label = f"large-query-{index}-{uuid.uuid4().hex[:6]}"
            started = time.perf_counter()
            source_logs = run_mpspdz(
                instance,
                args.config,
                1,
                args.mpspdz_home,
                log_label=label,
                compile_timeout=args.compile_timeout,
                runtime_timeout=args.runtime_timeout,
                protocol=args.protocol,
            )
            runner_wall_seconds = time.perf_counter() - started
            logs_dir.mkdir(parents=True, exist_ok=True)
            logs: list[Path] = []
            for server, source_log in enumerate(source_logs):
                destination = logs_dir / f"server-{server}.log"
                shutil.copyfile(source_log, destination)
                os.chmod(destination, 0o600)
                logs.append(destination)

        decoded = decode_batch_logs(config.base, 1, logs)
        metrics = parse_party_zero_log(logs[0])
        exact = decoded == expected
        trial = {
            "trial": index,
            "query": query,
            "query_share_and_input_assembly_seconds": assembly_seconds,
            "private_input_bytes_all_servers": input_bytes,
            "runner_wall_seconds": runner_wall_seconds,
            "mpc_seconds_including_preprocessing": metrics["mpc_seconds"],
            "global_data_mb": metrics["global_data_mb"],
            "party0_data_mb": metrics["party_0_data_mb"],
            "party0_reported_rounds": metrics["reported_rounds"],
            "exact_oracle_match": exact,
            "fields_compared": config.base.top_k * 4,
        }
        write_json(trial_dir / "expected.json", expected, private=True)
        write_json(trial_dir / "decoded.json", decoded, private=True)
        write_json(trial_dir / "summary.json", trial)
        trials.append(trial)
        print(
            f"[{index}/{len(queries)}] {query['source']}: "
            f"{metrics['mpc_seconds']:.3f}s, {metrics['global_data_mb']:.3f} MB, exact={exact}",
            flush=True,
        )
        if not exact:
            raise RuntimeError(f"trial {index} disagrees with the independent oracle")

    report = {
        "name": "relation_paged_large_distinct_query_sweep",
        "date": time.strftime("%Y-%m-%d", time.gmtime()),
        "protocol": args.protocol,
        "config": str(args.config),
        "owners": len(config.base.owners),
        "entities": len(config.base.entities),
        "relations": len(config.base.relations),
        "distinct_queries": len(queries),
        "scope_warning": (
            "Distinct queries reuse one fixed owner-share epoch and one compiled circuit. "
            "Three MPC parties execute on one localhost and timings include protocol "
            "preprocessing but exclude owner preparation, input assembly, and compilation."
        ),
        "oracle_input_reconstruction": (
            "All three owner page shares were combined offline to recover exact input "
            "target/relation/score fields before running the independent cleartext evaluator."
            if args.recover_edge_fields_from_owner_shards
            else "The retained clear owner-edge files were used directly."
        ),
        "aggregate": aggregate(trials),
        "trials": trials,
    }
    write_json(args.output_dir / "report.json", report)
    print(f"wrote {args.output_dir / 'report.json'}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
