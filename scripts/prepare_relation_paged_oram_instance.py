#!/usr/bin/env python3
"""Prepare a centralized benchmark instance for relation-paged recursive ORAM.

Deployment owners should each run ``write_owner_shards()`` locally.  This tool
sees all plaintext owner files only to make reproducible single-host evaluation
possible; the manifest records that scope limitation explicitly.
"""

from __future__ import annotations

import argparse
import gc
import json
import secrets
import shutil
import sys
import time
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from doram_t2_3pc.relation_paged_oram import build_owner_relation_paged_oram
from doram_t2_3pc.relation_paged_oram_epoch import RelationPagedOramEpochAuthorization
from doram_t2_3pc.relation_paged_oram_program import planned_shape, program_name, write_program
from doram_t2_3pc.relation_paged_oram_shares import (
    create_query_shards,
    shape_for_owner,
    write_owner_shards,
)
from doram_t2_3pc.relation_pages import (
    RelationPageConfig,
    check_global_frontier,
    evaluate_paged_cleartext,
)


def _json_rows(path: Path, label: str) -> list[dict[str, object]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(value, dict) and label == "queries":
        value = [value]
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise ValueError(f"{label} must be a JSON list of objects")
    return value


def _owner_paths(values: list[str], owners: tuple[str, ...]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        owner, separator, raw_path = value.partition("=")
        if not separator or not owner or not raw_path:
            raise ValueError("--owner-edges requires OWNER=PATH")
        if owner in result:
            raise ValueError(f"duplicate edge file for owner {owner!r}")
        result[owner] = Path(raw_path).resolve()
    if set(result) != set(owners):
        raise ValueError("--owner-edges must provide every configured owner exactly once")
    return result


def _append(source: Path, destination) -> None:
    with source.open("rb") as stream:
        shutil.copyfileobj(stream, destination, length=8 * 1024 * 1024)


def prepare_instance(
    config_path: str | Path,
    queries_path: str | Path,
    owner_edge_paths: dict[str, Path],
    output_dir: str | Path,
    *,
    chi: int = 256,
    base_threshold: int = 64,
    statistical_security_bits: int = 80,
    epoch_id: str | None = None,
) -> dict[str, object]:
    config = RelationPageConfig.load(config_path)
    if set(owner_edge_paths) != set(config.base.owners):
        raise ValueError("owner paths do not match the configured federation")
    raw_queries = _json_rows(Path(queries_path), "queries")
    queries = [{str(key): str(value) for key, value in row.items()} for row in raw_queries]
    shape = planned_shape(
        config,
        len(queries),
        chi=chi,
        base_threshold=base_threshold,
        statistical_security_bits=statistical_security_bits,
    )
    output = Path(output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    final_inputs = [output / f"Input-P{server}-0" for server in range(3)]
    protected = final_inputs + [output / "manifest.json"]
    if any(path.exists() for path in protected):
        raise FileExistsError("refusing to overwrite an existing dual-ORAM epoch")

    epoch = epoch_id or secrets.token_hex(32)
    segments: list[list[Path]] = [[] for _ in range(3)]
    owner_timings: dict[str, dict[str, float | int]] = {}
    clear_edges: dict[str, list[dict[str, object]]] = {}
    started = time.perf_counter()
    for owner_index, owner in enumerate(config.base.owners):
        edges = _json_rows(owner_edge_paths[owner], f"edges for {owner}")
        clear_edges[owner] = edges
        build_started = time.perf_counter()
        prepared = build_owner_relation_paged_oram(
            config,
            owner,
            edges,
            chi=chi,
            base_threshold=base_threshold,
            statistical_security_bits=statistical_security_bits,
        )
        if shape_for_owner(config, prepared, query_count=len(queries)) != shape:
            raise AssertionError("owner dual-ORAM does not match its planned public shape")
        built = time.perf_counter()
        owner_segments = [
            output / f".{owner}-P{server}.dual.segment" for server in range(3)
        ]
        write_owner_shards(prepared, owner_segments, modulus=config.base.field_prime)
        shared = time.perf_counter()
        for server, path in enumerate(owner_segments):
            segments[server].append(path)
        owner_timings[owner] = {
            "edges": len(edges),
            "realized_pages": prepared.layout.realized_page_count,
            "build_seconds": round(built - build_started, 6),
            "share_write_seconds": round(shared - built, 6),
        }
        del prepared
        gc.collect()

    # This centralized evaluation builder already sees the plaintext union, so
    # it has no excuse to trust a claimed zero. Deployment uses the separate
    # one-time MPC bound gate over owner occupancy shares.
    bound_report = check_global_frontier(config, clear_edges)
    authorization = RelationPagedOramEpochAuthorization.accepted(
        config, epoch_id=epoch, query_count=len(queries), bound_violations=0
    )

    query_shards = create_query_shards(config, queries, epoch_id=epoch)
    temporary = [output / f".Input-P{server}-0.tmp" for server in range(3)]
    try:
        for server in range(3):
            with temporary[server].open("xb") as destination:
                for segment in segments[server]:
                    _append(segment, destination)
                for value in query_shards[server].values:
                    destination.write(f"{value}\n".encode("ascii"))
                destination.flush()
            temporary[server].replace(final_inputs[server])
            final_inputs[server].chmod(0o600)
    finally:
        for server_segments in segments:
            for segment in server_segments:
                segment.unlink(missing_ok=True)
        for path in temporary:
            path.unlink(missing_ok=True)

    expected = [
        evaluate_paged_cleartext(config, clear_edges, query) for query in queries
    ]
    name = program_name(config, shape, len(queries))
    source = write_program(config, shape, len(queries), output / f"{name}.mpc")
    manifest: dict[str, object] = {
        "backend": "relation-paged-recursive-readonly-oram",
        "config_source": str(Path(config_path).resolve()),
        "queries_source": str(Path(queries_path).resolve()),
        "program": name,
        "source": str(source),
        "epoch_authorization": asdict(authorization),
        "shape": asdict(shape),
        "shape_options": {
            "chi": chi,
            "base_threshold": base_threshold,
            "statistical_security_bits": statistical_security_bits,
        },
        "owner_values_per_server": shape.owner_values * len(config.base.owners),
        "query_values_per_server": len(queries) * 3,
        "input_bytes_per_server": [path.stat().st_size for path in final_inputs],
        "owner_setup": owner_timings,
        "global_frontier_check": bound_report,
        "expected": expected,
        "total_prepare_seconds": round(time.perf_counter() - started, 6),
        "scope_warning": (
            "Centralized benchmark preparation; deployed owners independently "
            "construct and share their own directory and page stacks"
        ),
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--queries", required=True, type=Path)
    parser.add_argument("--owner-edges", action="append", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--chi", type=int, default=256)
    parser.add_argument("--base-threshold", type=int, default=64)
    parser.add_argument("--statistical-security-bits", type=int, default=80)
    args = parser.parse_args()
    config = RelationPageConfig.load(args.config)
    manifest = prepare_instance(
        args.config,
        args.queries,
        _owner_paths(args.owner_edges, config.base.owners),
        args.output_dir,
        chi=args.chi,
        base_threshold=args.base_threshold,
        statistical_security_bits=args.statistical_security_bits,
    )
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
