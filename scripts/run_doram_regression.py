#!/usr/bin/env python3
"""Run repeatable packed-scan DORAM regressions in batches of at most ten."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
import uuid
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from doram_t2_3pc.config import PublicConfig  # noqa: E402
from doram_t2_3pc.decode_batch import decode_batch_logs  # noqa: E402
from doram_t2_3pc.io import read_json  # noqa: E402
from doram_t2_3pc.packed import (  # noqa: E402
    assemble_packed_batch_from_paths,
    create_packed_owner_shards,
    create_packed_query_batch_shards,
)
from doram_t2_3pc.reference import evaluate_cleartext  # noqa: E402
from doram_t2_3pc.run_scan_mpspdz import run as run_local_mpspdz  # noqa: E402
from doram_t2_3pc.scan_program import MAX_BATCH_QUERIES, program_name  # noqa: E402


DEFAULT_METAQA_FIXTURE = Path("/tmp/doram-metaqa-cap2-q10")
DEFAULT_MPSPDZ = ROOT.parent / "SimGRAG" / "external" / "MP-SPDZ"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run the three-party packed-scan DORAM over the diverse fixture, "
            "the bounded-fanout MetaQA fixture, or both"
        )
    )
    parser.add_argument(
        "--dataset", choices=("diverse", "metaqa", "both"), default="both"
    )
    parser.add_argument("--query-count", type=int, default=250)
    parser.add_argument("--batch-size", type=int, default=10)
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Run directory; defaults to results/doram_regression_<UTC timestamp>",
    )
    parser.add_argument("--mpspdz-home", type=Path, default=DEFAULT_MPSPDZ)
    parser.add_argument(
        "--metaqa-fixture-dir", type=Path, default=DEFAULT_METAQA_FIXTURE
    )
    parser.add_argument("--compile-timeout", type=int, default=1800)
    parser.add_argument("--runtime-timeout", type=int, default=3600)
    parser.add_argument(
        "--max-batches",
        type=int,
        help="Run only this many pending batches per dataset (useful for a smoke test)",
    )
    parser.add_argument(
        "--prepare-only",
        action="store_true",
        help="Create shares and MP-SPDZ input files without launching MPC",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Skip completed batches in an existing output directory",
    )
    return parser.parse_args()


def write_json(path: Path, value: Any, *, private: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(temporary, flags, 0o600 if private else 0o644)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def load_json_list(path: Path, description: str) -> list[Any]:
    value = read_json(path)
    if not isinstance(value, list) or not value:
        raise ValueError(f"{description} must be a non-empty JSON list: {path}")
    return value


def repeated(values: list[Any], count: int) -> tuple[list[Any], list[int]]:
    if count < 1:
        raise ValueError("query_count must be positive")
    return (
        [values[index % len(values)] for index in range(count)],
        [index % len(values) for index in range(count)],
    )


def diverse_spec(dataset_dir: Path, query_count: int) -> dict[str, Any]:
    fixture = ROOT / "doram_t2_3pc" / "examples" / "ten_query"
    config_path = fixture / "config_scalable.json"
    config = PublicConfig.load(config_path)
    base_queries = load_json_list(fixture / "queries.json", "diverse queries")
    queries, base_indices = repeated(base_queries, query_count)

    owner_edges: dict[str, list[dict[str, Any]]] = {}
    owner_shards: list[list[Path]] = []
    for owner_index, owner in enumerate(config.owners):
        edge_path = fixture / f"{owner}.json"
        edges = load_json_list(edge_path, f"edges for {owner}")
        owner_edges[owner] = edges
        shard_dir = dataset_dir / "owner-shards" / owner
        paths = create_packed_owner_shards(config, owner, edge_path, shard_dir)
        if any(f"packed-owner-{owner_index}-" not in path.name for path in paths):
            raise AssertionError("unexpected owner-shard naming")
        owner_shards.append(paths)

    base_expected = [
        evaluate_cleartext(config, owner_edges, query) for query in base_queries
    ]
    expected = [base_expected[index] for index in base_indices]
    return {
        "config": config,
        "config_path": config_path,
        "base_queries": base_queries,
        "queries": queries,
        "base_indices": base_indices,
        "expected": expected,
        "owner_shards": owner_shards,
        "scope": "ten-query diverse fixture repeated cyclically",
    }


def metaqa_spec(
    dataset_dir: Path, fixture: Path, query_count: int
) -> dict[str, Any]:
    fixture = fixture.resolve()
    config_path = fixture / "config.json"
    config = PublicConfig.load(config_path)
    base_queries = load_json_list(fixture / "queries.json", "MetaQA queries")
    base_expected = load_json_list(fixture / "reference.json", "MetaQA reference")
    if len(base_expected) != len(base_queries):
        raise ValueError("MetaQA queries and reference have different lengths")
    queries, base_indices = repeated(base_queries, query_count)
    expected = [base_expected[index] for index in base_indices]

    owner_shards: list[list[Path]] = []
    for owner_index, owner in enumerate(config.owners):
        shard_dir = fixture / f"shares-{owner}"
        paths = [
            shard_dir / f"packed-owner-{owner_index}-to-server-{server}.json"
            for server in range(3)
        ]
        if any(not path.is_file() for path in paths):
            raise FileNotFoundError(
                f"MetaQA owner shares are incomplete for {owner}: {shard_dir}"
            )
        owner_shards.append(paths)

    return {
        "config": config,
        "config_path": config_path,
        "base_queries": base_queries,
        "queries": queries,
        "base_indices": base_indices,
        "expected": expected,
        "owner_shards": owner_shards,
        "scope": (
            "ten selected cap-preserving queries repeated cyclically over the "
            "deterministic fanout-two MetaQA snapshot"
        ),
    }


def owner_paths_for_server(owner_shards: list[list[Path]], server: int) -> list[Path]:
    return [paths[server] for paths in owner_shards]


def batch_is_complete(batch_dir: Path, expected_count: int) -> bool:
    summary_path = batch_dir / "batch_summary.json"
    decoded_path = batch_dir / "decoded.json"
    if not summary_path.is_file() or not decoded_path.is_file():
        return False
    try:
        summary = read_json(summary_path)
        decoded = read_json(decoded_path)
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    return (
        isinstance(summary, dict)
        and summary.get("status") == "completed"
        and isinstance(decoded, list)
        and len(decoded) == expected_count
    )


def run_dataset(
    name: str,
    dataset_dir: Path,
    args: argparse.Namespace,
    run_token: str,
) -> None:
    dataset_dir.mkdir(parents=True, exist_ok=True)
    spec = (
        diverse_spec(dataset_dir, args.query_count)
        if name == "diverse"
        else metaqa_spec(dataset_dir, args.metaqa_fixture_dir, args.query_count)
    )
    config: PublicConfig = spec["config"]
    queries: list[dict[str, str]] = spec["queries"]
    expected: list[list[dict[str, int]]] = spec["expected"]
    batch_count = (len(queries) + args.batch_size - 1) // args.batch_size

    manifest_path = dataset_dir / "run_manifest.json"
    manifest = {
        "version": 1,
        "dataset": name,
        "scope": spec["scope"],
        "run_token": run_token,
        "query_count": len(queries),
        "unique_base_queries": len(spec["base_queries"]),
        "batch_size": args.batch_size,
        "batch_count": batch_count,
        "config": str(Path(spec["config_path"]).resolve()),
        "config_digest": config.digest,
        "program_for_full_batch": program_name(config, args.batch_size),
        "mpspdz_home": str(args.mpspdz_home.resolve()),
        "prepare_only": args.prepare_only,
        "rounds_warning": (
            "MP-SPDZ reports multithreaded rounds with double counting; they are "
            "not sequential WAN round trips."
        ),
    }
    if manifest_path.exists() and args.resume:
        previous = read_json(manifest_path)
        if not isinstance(previous, dict) or any(
            previous.get(key) != manifest[key]
            for key in ("dataset", "query_count", "batch_size", "config_digest")
        ):
            raise ValueError(f"resume manifest is incompatible: {manifest_path}")
    else:
        write_json(manifest_path, manifest)

    write_json(dataset_dir / "queries.json", queries)
    write_json(dataset_dir / "expected.json", expected)
    write_json(dataset_dir / "base_query_indices.json", spec["base_indices"])

    executed = 0
    for batch_index in range(batch_count):
        start = batch_index * args.batch_size
        stop = min(start + args.batch_size, len(queries))
        batch_queries = queries[start:stop]
        batch_expected = expected[start:stop]
        batch_dir = dataset_dir / f"batch-{batch_index:03d}"
        if args.resume and batch_is_complete(batch_dir, len(batch_queries)):
            print(f"[{name}] batch {batch_index + 1}/{batch_count}: already completed")
            continue
        if args.max_batches is not None and executed >= args.max_batches:
            break

        query_path = batch_dir / "queries.json"
        query_shard_dir = batch_dir / "query-shards"
        instance_dir = batch_dir / "instance"
        logs_dir = batch_dir / "logs"
        write_json(query_path, batch_queries, private=True)
        query_shards = create_packed_query_batch_shards(
            config, query_path, query_shard_dir
        )
        for server in range(3):
            assemble_packed_batch_from_paths(
                config,
                server,
                len(batch_queries),
                query_shards[server],
                owner_paths_for_server(spec["owner_shards"], server),
                instance_dir / f"Input-P{server}-0",
            )

        prepared = {
            "status": "prepared",
            "dataset": name,
            "batch_index": batch_index,
            "global_query_start": start,
            "query_count": len(batch_queries),
            "program": program_name(config, len(batch_queries)),
            "expected": batch_expected,
        }
        write_json(batch_dir / "batch_summary.json", prepared)
        print(f"[{name}] batch {batch_index + 1}/{batch_count}: prepared")
        executed += 1
        if args.prepare_only:
            continue

        # A fresh attempt suffix lets --resume retry a batch even if MP-SPDZ
        # preserved logs from an interrupted earlier attempt.
        label = f"dreg-{name}-{run_token}-b{batch_index:03d}-{uuid.uuid4().hex[:4]}"
        started = time.perf_counter()
        try:
            source_logs = run_local_mpspdz(
                instance_dir,
                spec["config_path"],
                len(batch_queries),
                args.mpspdz_home,
                log_label=label,
                compile_timeout=args.compile_timeout,
                runtime_timeout=args.runtime_timeout,
            )
            logs_dir.mkdir(parents=True, exist_ok=True)
            local_logs = []
            for server, source in enumerate(source_logs):
                destination = logs_dir / f"server-{server}.log"
                shutil.copyfile(source, destination)
                os.chmod(destination, 0o600)
                local_logs.append(destination)
            decoded = decode_batch_logs(config, len(batch_queries), local_logs)
            write_json(batch_dir / "decoded.json", decoded, private=True)
            matches = [actual == wanted for actual, wanted in zip(decoded, batch_expected)]
            completed = {
                **prepared,
                "status": "completed",
                "wall_seconds": time.perf_counter() - started,
                "correct_queries": sum(matches),
                "all_queries_correct": all(matches),
                "per_query_reference_match": matches,
                "logs": [str(path.resolve()) for path in local_logs],
            }
            write_json(batch_dir / "batch_summary.json", completed)
            print(
                f"[{name}] batch {batch_index + 1}/{batch_count}: completed; "
                f"correct={sum(matches)}/{len(matches)}; "
                f"wall={completed['wall_seconds']:.3f}s"
            )
        except BaseException as exc:
            failed = {
                **prepared,
                "status": "failed",
                "wall_seconds": time.perf_counter() - started,
                "error_type": type(exc).__name__,
                "error": str(exc),
            }
            write_json(batch_dir / "batch_summary.json", failed)
            raise


def main() -> int:
    args = parse_args()
    if not 1 <= args.batch_size <= MAX_BATCH_QUERIES:
        raise SystemExit(f"--batch-size must be in [1, {MAX_BATCH_QUERIES}]")
    if args.query_count < 1:
        raise SystemExit("--query-count must be positive")
    if args.max_batches is not None and args.max_batches < 1:
        raise SystemExit("--max-batches must be positive")

    timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    output_dir = (
        args.output_dir.resolve()
        if args.output_dir
        else (ROOT / "results" / f"doram_regression_{timestamp}").resolve()
    )
    if output_dir.exists() and not args.resume:
        raise SystemExit(f"output directory already exists (use --resume): {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(output_dir, 0o700)

    root_manifest_path = output_dir / "run_manifest.json"
    if args.resume and root_manifest_path.is_file():
        root_manifest = read_json(root_manifest_path)
        if not isinstance(root_manifest, dict) or not root_manifest.get("run_token"):
            raise SystemExit("invalid root resume manifest")
        run_token = str(root_manifest["run_token"])
    else:
        run_token = uuid.uuid4().hex[:8]
        write_json(
            root_manifest_path,
            {
                "version": 1,
                "dataset_selection": args.dataset,
                "run_token": run_token,
                "created_utc": timestamp,
                "query_count_per_dataset": args.query_count,
                "batch_size": args.batch_size,
            },
        )

    datasets = ("diverse", "metaqa") if args.dataset == "both" else (args.dataset,)
    for dataset in datasets:
        run_dataset(dataset, output_dir / dataset, args, run_token)
    print(f"Run directory: {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
