#!/usr/bin/env python3
"""Run repeatable oblivious-lookup regressions in batches of at most ten.

The supported backend is the packed MPC-oblivious linear scan. ``--backend
relation-paged`` runs the same regression against the EXPERIMENTAL relation-paged
layout instead; both backends answer identical queries and are checked against
their own independent cleartext oracle, so a cross-backend comparison of
``decoded.json`` is meaningful.
"""

from __future__ import annotations

import argparse
import hashlib
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
from doram_t2_3pc.page_program import (  # noqa: E402
    program_name as paged_program_name,
    render_program as paged_render_program,
)
from doram_t2_3pc.paged_shares import (  # noqa: E402
    assemble_paged_batch_from_paths,
    create_paged_owner_shards,
)
from doram_t2_3pc.protocols import DEFAULT_PROTOCOL, PROTOCOLS  # noqa: E402
from doram_t2_3pc.reference import evaluate_cleartext  # noqa: E402
from doram_t2_3pc.relation_pages import (  # noqa: E402
    RelationPageConfig,
    evaluate_paged_cleartext,
)
from doram_t2_3pc.run_pages_mpspdz import run as run_paged_mpspdz  # noqa: E402
from doram_t2_3pc.run_scan_mpspdz import run as run_local_mpspdz  # noqa: E402
from doram_t2_3pc.scan_program import (  # noqa: E402
    MAX_BATCH_QUERIES,
    program_name,
    render_program,
)


DEFAULT_METAQA_FIXTURE = Path("/tmp/doram-metaqa-cap2-q10")
DEFAULT_MPSPDZ = ROOT.parent / "SimGRAG" / "external" / "MP-SPDZ"


class Backend:
    """Everything that differs between the two storage layouts.

    Both backends share the client-facing contract: identical query shards,
    identical ``DORAM_BATCH_SHARE`` output lines, identical decoding. Only the
    server-side layout, its cleartext oracle, and the generated circuit differ.
    """

    def __init__(self, key: str) -> None:
        if key not in ("packed-scan", "relation-paged"):
            raise ValueError(f"unknown backend: {key}")
        self.key = key
        self.paged = key == "relation-paged"
        self.owner_shard_prefix = "paged-owner-" if self.paged else "packed-owner-"
        self.config_basename = (
            "config_relation_pages.json" if self.paged else "config_scalable.json"
        )
        self.status = (
            "EXPERIMENTAL relation-paged two-level layout"
            if self.paged
            else "supported packed MPC-oblivious linear scan"
        )

    def load_config(self, path: Path) -> Any:
        return RelationPageConfig.load(path) if self.paged else PublicConfig.load(path)

    def base_config(self, config: Any) -> PublicConfig:
        """The shared public config used for query shards and decoding."""

        return config.base if self.paged else config

    def create_owner_shards(
        self, config: Any, owner: str, edge_path: Path, shard_dir: Path
    ) -> list[Path]:
        builder = create_paged_owner_shards if self.paged else create_packed_owner_shards
        return builder(config, owner, edge_path, shard_dir)

    def assemble(
        self,
        config: Any,
        server: int,
        query_count: int,
        query_shard: Path,
        owner_shards: list[Path],
        output: Path,
    ) -> Any:
        assembler = (
            assemble_paged_batch_from_paths
            if self.paged
            else assemble_packed_batch_from_paths
        )
        return assembler(
            config, server, query_count, query_shard, owner_shards, output
        )

    def program_name(self, config: Any, query_count: int) -> str:
        namer = paged_program_name if self.paged else program_name
        return namer(config, query_count)

    def render_program(self, config: Any, query_count: int) -> str:
        renderer = paged_render_program if self.paged else render_program
        return renderer(config, query_count)

    def evaluate_cleartext(
        self, config: Any, owner_edges: dict[str, list[dict[str, Any]]], query: dict
    ) -> list[dict[str, int]]:
        oracle = evaluate_paged_cleartext if self.paged else evaluate_cleartext
        return oracle(config, owner_edges, query)

    def run(self, *call_args: Any, **call_kwargs: Any) -> list[Path]:
        runner = run_paged_mpspdz if self.paged else run_local_mpspdz
        return runner(*call_args, **call_kwargs)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run the three-party packed oblivious scan over the diverse fixture, "
            "the bounded-fanout MetaQA fixture, or both"
        )
    )
    parser.add_argument(
        "--dataset", choices=("diverse", "metaqa", "both"), default="both"
    )
    parser.add_argument(
        "--backend",
        choices=("packed-scan", "relation-paged"),
        default="packed-scan",
        help=(
            "Storage layout under test; relation-paged is EXPERIMENTAL and "
            "currently supported only for the diverse fixture"
        ),
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
        "--protocol",
        default=DEFAULT_PROTOCOL,
        choices=sorted(PROTOCOLS),
        help=(
            "MP-SPDZ protocol for relation-paged runs. The packed-scan runner "
            "currently supports only semi. Use the same protocol for A/B results."
        ),
    )
    parser.add_argument(
        "--diverse-config",
        type=Path,
        help=(
            "Override the ten-query public config. This is required for a "
            "field-matched Temi/Hemi comparison because old shares use a "
            "non-HE-compatible prime."
        ),
    )
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


def document_digest(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def program_source_digest(
    config: Any, query_count: int, backend: Backend
) -> str:
    return hashlib.sha256(
        backend.render_program(config, query_count).encode("utf-8")
    ).hexdigest()


def repeated(values: list[Any], count: int) -> tuple[list[Any], list[int]]:
    if count < 1:
        raise ValueError("query_count must be positive")
    return (
        [values[index % len(values)] for index in range(count)],
        [index % len(values) for index in range(count)],
    )


def diverse_spec(
    dataset_dir: Path,
    query_count: int,
    backend: Backend,
    *,
    resume: bool = False,
    config_override: Path | None = None,
) -> dict[str, Any]:
    fixture = ROOT / "doram_t2_3pc" / "examples" / "ten_query"
    config_path = (
        config_override.resolve()
        if config_override is not None
        else fixture / backend.config_basename
    )
    config = backend.load_config(config_path)
    owners = backend.base_config(config).owners
    base_queries = load_json_list(fixture / "queries.json", "diverse queries")
    queries, base_indices = repeated(base_queries, query_count)

    owner_edges: dict[str, list[dict[str, Any]]] = {}
    owner_shards: list[list[Path]] = []
    for owner_index, owner in enumerate(owners):
        edge_path = fixture / f"{owner}.json"
        edges = load_json_list(edge_path, f"edges for {owner}")
        owner_edges[owner] = edges
        shard_dir = dataset_dir / "owner-shards" / owner
        prefix = f"{backend.owner_shard_prefix}{owner_index}-"
        expected_paths = [
            shard_dir / f"{prefix}to-server-{server}.json" for server in range(3)
        ]
        if resume:
            if any(not path.is_file() for path in expected_paths):
                raise FileNotFoundError(
                    f"cannot resume with incomplete owner shards for {owner}"
                )
            paths = expected_paths
        else:
            paths = backend.create_owner_shards(config, owner, edge_path, shard_dir)
        if any(prefix not in path.name for path in paths):
            raise AssertionError("unexpected owner-shard naming")
        owner_shards.append(paths)

    base_expected = [
        backend.evaluate_cleartext(config, owner_edges, query)
        for query in base_queries
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
        "reference_kind": "independent raw-edge oracle over supplied owner files",
        "scope": "ten-query diverse fixture repeated cyclically",
    }


def metaqa_spec(
    dataset_dir: Path, fixture: Path, query_count: int
) -> dict[str, Any]:
    fixture = fixture.resolve()
    config_path = fixture / "config.json"
    config = PublicConfig.load(config_path)
    base_queries = load_json_list(fixture / "queries.json", "MetaQA queries")
    stored_expected = load_json_list(
        fixture / "reference.json", "MetaQA reference"
    )
    if len(stored_expected) != len(base_queries):
        raise ValueError("MetaQA queries and reference have different lengths")

    owner_shards: list[list[Path]] = []
    raw_owner_edges: dict[str, list[dict[str, Any]]] = {}
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
        raw_owner_path = fixture / f"{owner}.json"
        if raw_owner_path.is_file():
            raw_owner_edges[owner] = load_json_list(
                raw_owner_path, f"bounded MetaQA edges for {owner}"
            )

    if len(raw_owner_edges) == len(config.owners):
        base_expected = [
            evaluate_cleartext(config, raw_owner_edges, query)
            for query in base_queries
        ]
        if base_expected != stored_expected:
            raise ValueError(
                "independent raw-edge oracle disagrees with MetaQA reference.json"
            )
        reference_kind = (
            "independent raw-edge oracle over supplied bounded owner files; "
            "reference.json checked for exact agreement"
        )
    else:
        base_expected = stored_expected
        reference_kind = (
            "precomputed bounded reference.json; raw owner files unavailable "
            "for an independent oracle"
        )

    queries, base_indices = repeated(base_queries, query_count)
    expected = [base_expected[index] for index in base_indices]

    return {
        "config": config,
        "config_path": config_path,
        "base_queries": base_queries,
        "queries": queries,
        "base_indices": base_indices,
        "expected": expected,
        "owner_shards": owner_shards,
        "reference_kind": reference_kind,
        "scope": (
            "ten selected cap-preserving queries repeated cyclically over the "
            "deterministic fanout-two MetaQA snapshot"
        ),
    }


def owner_paths_for_server(owner_shards: list[list[Path]], server: int) -> list[Path]:
    return [paths[server] for paths in owner_shards]


def batch_is_complete(
    batch_dir: Path,
    expected_count: int,
    expected_program: str,
    expected_program_source_digest: str,
    query_digest: str,
    expected_digest: str,
) -> bool:
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
        and summary.get("all_outputs_match_bounded_reference") is True
        and summary.get("program") == expected_program
        and summary.get("program_source_digest")
        == expected_program_source_digest
        and summary.get("query_digest") == query_digest
        and summary.get("expected_digest") == expected_digest
        and isinstance(decoded, list)
        and len(decoded) == expected_count
        and document_digest(decoded) == expected_digest
    )


def run_dataset(
    name: str,
    dataset_dir: Path,
    args: argparse.Namespace,
    run_token: str,
) -> None:
    dataset_dir.mkdir(parents=True, exist_ok=True)
    backend = Backend(args.backend)
    if backend.paged and name != "diverse":
        # The MetaQA fixture ships pre-built packed shards only; re-sharding it
        # for the paged layout needs raw edges that are not in the tree.
        raise ValueError(
            "the relation-paged backend currently supports only the diverse "
            "fixture; the MetaQA fixture ships packed shards only"
        )
    spec = (
        diverse_spec(
            dataset_dir,
            args.query_count,
            backend,
            resume=args.resume,
            config_override=args.diverse_config,
        )
        if name == "diverse"
        else metaqa_spec(dataset_dir, args.metaqa_fixture_dir, args.query_count)
    )
    config = spec["config"]
    base_config: PublicConfig = backend.base_config(config)
    queries: list[dict[str, str]] = spec["queries"]
    expected: list[list[dict[str, int]]] = spec["expected"]
    batch_count = (len(queries) + args.batch_size - 1) // args.batch_size

    manifest_path = dataset_dir / "run_manifest.json"
    distinct_query_count = len(
        {
            json.dumps(query, sort_keys=True, separators=(",", ":"))
            for query in queries
        }
    )
    queries_digest = document_digest(queries)
    expected_digest = document_digest(expected)
    full_program_source_digest = program_source_digest(
        config, args.batch_size, backend
    )
    owner_shard_digests = [
        [file_digest(path) for path in owner_paths]
        for owner_paths in spec["owner_shards"]
    ]
    manifest = {
        "version": 3,
        "dataset": name,
        "backend": backend.key,
        "backend_status": backend.status,
        "protocol": args.protocol,
        "protocol_security": PROTOCOLS[args.protocol].describe(),
        "scope": spec["scope"],
        "reference_kind": spec["reference_kind"],
        "run_token": run_token,
        "query_count": len(queries),
        "execution_count": len(queries),
        "distinct_query_count": distinct_query_count,
        "unique_base_queries": len(spec["base_queries"]),
        "correctness_unit": (
            "MPC executions; repeated occurrences of one semantic query count "
            "separately"
        ),
        "batch_size": args.batch_size,
        "batch_count": batch_count,
        "config": str(Path(spec["config_path"]).resolve()),
        "config_digest": config.digest,
        "program_for_full_batch": backend.program_name(config, args.batch_size),
        "program_source_digest_for_full_batch": full_program_source_digest,
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
            for key in (
                "dataset",
                "backend",
                "protocol",
                "query_count",
                "batch_size",
                "config_digest",
                "program_for_full_batch",
                "program_source_digest_for_full_batch",
                "reference_kind",
            )
        ):
            raise ValueError(f"resume manifest is incompatible: {manifest_path}")
    else:
        write_json(manifest_path, manifest)

    resume_state_path = dataset_dir / ".resume_state.json"
    resume_state = {
        "version": 2,
        "backend": backend.key,
        "config_digest": config.digest,
        "queries_digest": queries_digest,
        "expected_digest": expected_digest,
        "owner_shard_digests": owner_shard_digests,
        "program_source_digest_for_full_batch": full_program_source_digest,
    }
    if args.resume:
        if not resume_state_path.is_file() or read_json(resume_state_path) != resume_state:
            raise ValueError(
                f"private resume state is missing or incompatible: {resume_state_path}"
            )
    else:
        write_json(resume_state_path, resume_state, private=True)

    write_json(dataset_dir / "queries.json", queries, private=True)
    write_json(dataset_dir / "expected.json", expected, private=True)
    write_json(
        dataset_dir / "base_query_indices.json",
        spec["base_indices"],
        private=True,
    )

    executed = 0
    for batch_index in range(batch_count):
        start = batch_index * args.batch_size
        stop = min(start + args.batch_size, len(queries))
        batch_queries = queries[start:stop]
        batch_expected = expected[start:stop]
        batch_dir = dataset_dir / f"batch-{batch_index:03d}"
        batch_program = backend.program_name(config, len(batch_queries))
        batch_program_source_digest = program_source_digest(
            config, len(batch_queries), backend
        )
        batch_query_digest = document_digest(batch_queries)
        batch_expected_digest = document_digest(batch_expected)
        if args.resume and batch_is_complete(
            batch_dir,
            len(batch_queries),
            batch_program,
            batch_program_source_digest,
            batch_query_digest,
            batch_expected_digest,
        ):
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
            base_config, query_path, query_shard_dir
        )
        for server in range(3):
            backend.assemble(
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
            "backend": backend.key,
            "batch_index": batch_index,
            "global_query_start": start,
            "query_count": len(batch_queries),
            "program": batch_program,
            "program_source_digest": batch_program_source_digest,
            "query_digest": batch_query_digest,
            "expected_digest": batch_expected_digest,
            "expected": batch_expected,
        }
        write_json(batch_dir / "batch_summary.json", prepared, private=True)
        print(f"[{name}] batch {batch_index + 1}/{batch_count}: prepared")
        executed += 1
        if args.prepare_only:
            continue

        # A fresh attempt suffix lets --resume retry a batch even if MP-SPDZ
        # preserved logs from an interrupted earlier attempt.
        label = f"dreg-{name}-{run_token}-b{batch_index:03d}-{uuid.uuid4().hex[:4]}"
        started = time.perf_counter()
        try:
            source_logs = backend.run(
                instance_dir,
                spec["config_path"],
                len(batch_queries),
                args.mpspdz_home,
                log_label=label,
                compile_timeout=args.compile_timeout,
                runtime_timeout=args.runtime_timeout,
                **({"protocol": args.protocol} if backend.paged else {}),
            )
            logs_dir.mkdir(parents=True, exist_ok=True)
            local_logs = []
            for server, source in enumerate(source_logs):
                destination = logs_dir / f"server-{server}.log"
                shutil.copyfile(source, destination)
                os.chmod(destination, 0o600)
                local_logs.append(destination)
            decoded = decode_batch_logs(base_config, len(batch_queries), local_logs)
            write_json(batch_dir / "decoded.json", decoded, private=True)
            matches = [actual == wanted for actual, wanted in zip(decoded, batch_expected)]
            completed = {
                **prepared,
                "status": "completed",
                "wall_seconds": time.perf_counter() - started,
                "reference_matching_executions": sum(matches),
                "all_outputs_match_bounded_reference": all(matches),
                "per_execution_reference_match": matches,
                "logs": [str(path.resolve()) for path in local_logs],
            }
            write_json(
                batch_dir / "batch_summary.json", completed, private=True
            )
            print(
                f"[{name}] batch {batch_index + 1}/{batch_count}: completed; "
                f"reference-match={sum(matches)}/{len(matches)} executions; "
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
            write_json(batch_dir / "batch_summary.json", failed, private=True)
            raise


def main() -> int:
    args = parse_args()
    if not 1 <= args.batch_size <= MAX_BATCH_QUERIES:
        raise SystemExit(f"--batch-size must be in [1, {MAX_BATCH_QUERIES}]")
    if args.query_count < 1:
        raise SystemExit("--query-count must be positive")
    if args.max_batches is not None and args.max_batches < 1:
        raise SystemExit("--max-batches must be positive")
    if args.backend == "relation-paged" and args.dataset != "diverse":
        raise SystemExit(
            "--backend relation-paged supports only --dataset diverse"
        )
    if args.backend == "packed-scan" and args.protocol != DEFAULT_PROTOCOL:
        raise SystemExit(
            "--backend packed-scan currently supports only --protocol semi"
        )

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
        recorded = root_manifest.get("backend", "packed-scan")
        if recorded != args.backend:
            raise SystemExit(
                "cannot resume a run recorded with a different backend: "
                f"{recorded} != {args.backend}"
            )
        if root_manifest.get("protocol", DEFAULT_PROTOCOL) != args.protocol:
            raise SystemExit("cannot resume a run recorded with a different protocol")
        run_token = str(root_manifest["run_token"])
    else:
        run_token = uuid.uuid4().hex[:8]
        write_json(
            root_manifest_path,
            {
                "version": 2,
                "dataset_selection": args.dataset,
                "backend": args.backend,
                "protocol": args.protocol,
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
