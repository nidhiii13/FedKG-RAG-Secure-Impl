#!/usr/bin/env python3
"""Prepare a benchmarkable end-to-end KG read-only-ORAM epoch.

This utility is a *centralized benchmark fixture builder*: it reads every
owner's plaintext edge file on one host.  The deployed role-separated path is
``create_owner_shards()``/``write_owner_stack_shards()``, where each owner runs
its part independently.  Keeping that distinction explicit prevents a local
evaluation convenience from becoming an unsupported privacy claim.
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

from doram_t2_3pc.kg_oram import build_owner_kg_oram
from doram_t2_3pc.kg_oram_program import (
    access_count_per_owner,
    planned_shape,
    program_name,
    write_program,
)
from doram_t2_3pc.kg_oram_shares import create_query_shards, write_owner_stack_shards
from doram_t2_3pc.oram_access import OramAccessShape
from doram_t2_3pc.oram_epoch import KgOramEpochAuthorization
from doram_t2_3pc.relation_pages import RelationPageConfig


def _json_list(path: Path, label: str) -> list[dict[str, object]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise ValueError(f"{label} must be a JSON list of objects")
    return value


def _queries(path: Path) -> list[dict[str, object]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise ValueError("queries must be one JSON object or a JSON list of objects")
    return value


def _parse_owner_edges(values: list[str], owners: tuple[str, ...]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        owner, separator, raw_path = value.partition("=")
        if not separator or not owner or not raw_path:
            raise ValueError("--owner-edges must have the form OWNER=PATH")
        if owner in result:
            raise ValueError(f"duplicate edge file for owner {owner!r}")
        result[owner] = Path(raw_path).resolve()
    if set(result) != set(owners):
        raise ValueError("--owner-edges must provide exactly every configured owner")
    return result


def _append_file(source: Path, destination) -> None:
    with source.open("rb") as stream:
        shutil.copyfileobj(stream, destination, length=8 * 1024 * 1024)


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
    owner_paths = _parse_owner_edges(args.owner_edges, config.base.owners)
    raw_queries = _queries(args.queries)
    queries = [{str(key): str(value) for key, value in row.items()} for row in raw_queries]
    shape = planned_shape(
        config,
        len(queries),
        chi=args.chi,
        base_threshold=args.base_threshold,
        statistical_security_bits=args.statistical_security_bits,
    )
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    final_inputs = [output / f"Input-P{server}-0" for server in range(3)]
    if any(path.exists() for path in final_inputs):
        raise FileExistsError("refusing to overwrite an existing KG-ORAM input epoch")

    epoch_id = secrets.token_hex(32)
    segments: list[list[Path]] = [[] for _ in range(3)]
    owner_timings: dict[str, dict[str, float | int]] = {}
    started = time.perf_counter()
    for owner_index, owner in enumerate(config.base.owners):
        edges = _json_list(owner_paths[owner], f"edges for {owner}")
        build_started = time.perf_counter()
        prepared = build_owner_kg_oram(
            config,
            owner,
            edges,
            chi=args.chi,
            base_threshold=args.base_threshold,
            statistical_security_bits=args.statistical_security_bits,
        )
        actual_shape = OramAccessShape.from_stack(
            prepared.stack,
            max_accesses=access_count_per_owner(config, len(queries)),
        )
        if actual_shape != shape:
            raise AssertionError("owner KG-ORAM does not match its public planned shape")
        built = time.perf_counter()
        owner_segments = [output / f".{owner}-P{server}.segment" for server in range(3)]
        write_owner_stack_shards(
            prepared, owner_segments, modulus=config.base.field_prime
        )
        shared = time.perf_counter()
        for server, path in enumerate(owner_segments):
            segments[server].append(path)
        owner_timings[owner] = {
            "edges": len(edges),
            "build_seconds": round(built - build_started, 6),
            "share_write_seconds": round(shared - built, 6),
        }
        del edges, prepared
        gc.collect()

    query_shards = create_query_shards(config, queries, epoch_id=epoch_id)
    temporary = [output / f".Input-P{server}-0.tmp" for server in range(3)]
    try:
        for server in range(3):
            with temporary[server].open("xb") as destination:
                for segment in segments[server]:
                    _append_file(segment, destination)
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

    authorization = KgOramEpochAuthorization.accepted(
        config,
        epoch_id=epoch_id,
        query_count=len(queries),
        bound_violations=0,
    )
    name = program_name(config, shape, len(queries))
    source = write_program(config, shape, len(queries), output / f"{name}.mpc")
    manifest = {
        "backend": "wide-record-recursive-readonly-kg-oram",
        "config_source": str(args.config.resolve()),
        "queries_source": str(args.queries.resolve()),
        "program": name,
        "source": str(source),
        "epoch_authorization": asdict(authorization),
        "shape": asdict(shape),
        "shape_options": {
            "chi": args.chi,
            "base_threshold": args.base_threshold,
            "statistical_security_bits": args.statistical_security_bits,
        },
        "owner_values_per_server": shape.owner_values * len(config.base.owners),
        "query_values_per_server": len(queries) * 3,
        "input_bytes_per_server": [path.stat().st_size for path in final_inputs],
        "owner_setup": owner_timings,
        "total_prepare_seconds": round(time.perf_counter() - started, 6),
        "scope_warning": (
            "Centralized benchmark fixture preparation; deployed owners must run "
            "the role-separated shard writer independently"
        ),
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
