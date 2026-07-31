#!/usr/bin/env python3
"""Run numeric threshold-PIR lookup with MP-SPDZ private record join/top-k."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.run_lattigo_threshold_pir_bucket_query import (
    _parse_edges,
    simplify_query_edges,
)
from src.crypto.hmac_ids import HmacIdProvider
from src.pir.lattigo_threshold_service import LattigoThresholdPirService
from src.semantic.relation_buckets import relation_bucket_tokens

TEMPLATE = ROOT / "mpspdz_client_excluded" / "programs" / "secure_numeric_pir_record_topk.mpc.template"
SELECTED_RE = re.compile(r"^\s*(\d+)\s+(\d+)\s*$")
TIME_RE = re.compile(r"Time\s*=\s*([0-9.]+)\s+seconds")
PARTY_DATA_RE = re.compile(r"Data sent\s*=\s*([0-9.]+)\s+MB\s+in\s+~?(\d+)\s+rounds")
GLOBAL_DATA_RE = re.compile(r"Global data sent\s*=\s*([0-9.]+)\s+MB")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Numeric PIR shared-record handoff to MP-SPDZ.")
    parser.add_argument("--index-dir", required=True, type=Path)
    parser.add_argument("--edge", action="append", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--key-env", default="FEDKG_SETUP_KEY")
    parser.add_argument("--semantic-bucket-mode", choices=("alias", "lsh", "hybrid"), default="alias")
    parser.add_argument("--max-query-buckets", type=int, default=1)
    parser.add_argument("--topk", type=int, default=3)
    parser.add_argument("--parties", type=int, default=3)
    parser.add_argument("--threshold", type=int, default=2)
    parser.add_argument("--share-modulus", type=int)
    parser.add_argument("--go-routines", type=int, default=8)
    parser.add_argument(
        "--mp-spdz-protocol",
        choices=("semi", "atlas"),
        default="semi",
        help="MP-SPDZ protocol backend for bounded traversal/top-k after PIR.",
    )
    parser.add_argument("--mp-spdz-home", type=Path, default=Path("external/MP-SPDZ"))
    parser.add_argument("--instance-dir", type=Path)
    parser.add_argument("--keep-instance", action="store_true")
    parser.add_argument("--debug-plan", action="store_true")
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument(
        "--lattigo-pir",
        type=Path,
        default=Path("tools/lattigo_threshold_pir/lattigo-fedkg-threshold-pir"),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.mp_spdz_home = _resolve_repo_relative(args.mp_spdz_home)
    started = time.perf_counter()
    ids = HmacIdProvider.from_env(args.key_env)
    metadata = json.loads((args.index_dir / "metadata.json").read_text())
    if metadata.get("record_format") != "json-u64-array":
        raise SystemExit("numeric runner requires an index built by build_numeric_pir_bucket_index.py")
    directory = json.loads((args.index_dir / "directory.json").read_text())
    id_map = json.loads((args.index_dir / "id_map.json").read_text())
    shards = metadata.get("shards") or []
    shard_records = [_load_numeric_records(args.index_dir / str(shard["path"])) for shard in shards]
    record_size = int(metadata["record_size"])
    logical_record_size = int(metadata.get("logical_record_size", record_size))
    page_capacity = int(metadata.get("page_capacity", 1))
    edge_cap = int(metadata["max_edges_per_record"])
    plaintext_modulus = int(metadata.get("plaintext_modulus", 65537))
    share_modulus = int(args.share_modulus or plaintext_modulus)

    original_edges = _parse_edges(args.edge)
    edges, simplification = simplify_query_edges(original_edges)
    if len(edges) not in (1, 2):
        raise SystemExit("numeric PIR MP-SPDZ runner supports one-hop or two-hop queries")
    edge_requests = _numeric_edge_requests(edges, ids, args, directory, len(shards))

    pir_start = time.perf_counter()
    shared_records, plaintext_records, requested_rows = _retrieve_all_shards(
        args,
        shards,
        shard_records,
        edge_requests,
        record_size,
        logical_record_size,
        plaintext_modulus,
    )
    pir_seconds = time.perf_counter() - pir_start

    instance_dir, temp_context = _instance_dir(args)
    try:
        mpc_start = time.perf_counter()
        _write_mpspdz_instance(
            shared_records,
            instance_dir,
            record_count=len(edges),
            records_per_edge=len(shards),
            record_size=logical_record_size,
            logical_record_size=logical_record_size,
            page_capacity=1,
            edge_cap=edge_cap,
            party_count=args.parties,
            share_modulus=share_modulus,
            topk=args.topk,
        )
        mpc_stdout = _run_mpspdz(
            instance_dir,
            args.mp_spdz_home,
            args.parties,
            args.timeout,
            protocol=args.mp_spdz_protocol,
        )
        mpc_seconds = time.perf_counter() - mpc_start
        edge_total = len(shards) * edge_cap
        selected_slots = _parse_selected_slots(mpc_stdout, sentinel=edge_total * edge_total)
        selected_paths = _decode_selected_paths(
            selected_slots,
            plaintext_records,
            edge_cap,
            len(shards),
            id_map,
        )
        payload = {
            "query": original_edges,
            "effective_query": edges,
            "query_simplification": simplification,
            "pir": {
                "backend": "lattigo-threshold-bgv-pir",
                "response": "additive numeric record shares",
                "shard_count": len(shards),
                "record_size": record_size,
                "edge_cap": edge_cap,
                "time_seconds": pir_seconds,
            },
            "mp_spdz": {
                "program": "secure_numeric_pir_record_topk",
                "protocol": args.mp_spdz_protocol,
                "selected_slots": selected_slots,
                "metrics": {**_parse_metrics(mpc_stdout), "wall_time_seconds": mpc_seconds},
            },
            "selected_paths": selected_paths,
            "selected_path_count": len(selected_paths),
            "total_seconds": time.perf_counter() - started,
            "security_boundary": (
                "PIR record contents are handed to MP-SPDZ as additive numeric slot shares; "
                "MP-SPDZ reveals only selected edge/pair slots."
            ),
        }
        if args.debug_plan:
            payload["pir"]["requested_rows_per_edge"] = requested_rows
        rendered = json.dumps(payload, indent=2, sort_keys=True)
        print(rendered)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered + "\n")
    finally:
        if temp_context is not None and not args.keep_instance:
            temp_context.cleanup()
    return 0


def _instance_dir(args: argparse.Namespace) -> tuple[Path, tempfile.TemporaryDirectory[str] | None]:
    if args.instance_dir is not None:
        args.instance_dir.mkdir(parents=True, exist_ok=True)
        return args.instance_dir, None
    temp_context = tempfile.TemporaryDirectory(prefix="fedkg-numeric-pir-mpspdz-")
    return Path(temp_context.name), temp_context


def _resolve_repo_relative(path: Path) -> Path:
    if path.is_absolute():
        return path
    return ROOT / path


def _load_numeric_records(path: Path) -> list[list[int]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _numeric_edge_requests(
    edges: list[tuple[str, str, str]],
    ids: HmacIdProvider,
    args: argparse.Namespace,
    directory: dict[str, dict[str, int]],
    shard_count: int,
) -> list[list[dict[str, int]]]:
    requests: list[list[dict[str, int]]] = []
    for source, relation, target in edges:
        rows = [{"row": 0, "offset": 0} for _ in range(shard_count)]
        buckets = relation_bucket_tokens(ids, relation, mode=args.semantic_bucket_mode)
        if args.max_query_buckets > 0:
            buckets = buckets[: args.max_query_buckets]
        if not source.strip().upper().startswith("UNKNOWN"):
            direction = "forward"
            entity_id = ids.entity_id(source)
        elif not target.strip().upper().startswith("UNKNOWN"):
            direction = "reverse"
            entity_id = ids.entity_id(target)
        else:
            raise ValueError("each numeric PIR edge must bind either source or target")
        matched = False
        for bucket in buckets:
            entry = directory.get(f"{direction}:{entity_id}:{bucket}")
            if entry is None:
                continue
            rows[int(entry["shard"])] = {"row": int(entry["row"]), "offset": int(entry.get("offset", 0))}
            matched = True
            break
        if not matched:
            raise SystemExit(f"no numeric PIR bucket found for edge {(source, relation, target)!r}")
        requests.append(rows)
    return requests


def _retrieve_all_shards(
    args: argparse.Namespace,
    shards: list[dict],
    shard_records: list[list[list[int]]],
    edge_requests: list[list[dict[str, int]]],
    record_size: int,
    logical_record_size: int,
    plaintext_modulus: int,
) -> tuple[list[dict], list[list[list[int]]], list[list[dict[str, int]]]]:
    shared_by_edge: list[list[dict | None]] = [[None for _ in shards] for _ in edge_requests]
    plaintext_by_edge: list[list[list[int]]] = [[[] for _ in shards] for _ in edge_requests]
    for shard_index, shard in enumerate(shards):
        indices = [edge_requests[edge_index][shard_index]["row"] for edge_index in range(len(edge_requests))]
        with LattigoThresholdPirService(
            executable=args.lattigo_pir,
            records_jsonl=args.index_dir / str(shard["path"]),
            record_size=record_size,
            parties=args.parties,
            threshold=args.threshold,
            go_routines=args.go_routines,
            record_format="json-u64-array",
            plaintext_modulus=plaintext_modulus,
            cwd=ROOT,
        ) as service:
            response = service.retrieve_shared(
                indices,
                share_parties=args.parties,
                share_modulus=int(args.share_modulus or plaintext_modulus),
            )
        for edge_index, record in enumerate(response.get("records", [])):
            offset = edge_requests[edge_index][shard_index]["offset"]
            shared_by_edge[edge_index][shard_index] = _slice_shared_record(
                record,
                offset,
                logical_record_size,
            )
            plaintext_by_edge[edge_index][shard_index] = _logical_record_at(
                shard_records[shard_index][indices[edge_index]],
                offset,
                logical_record_size,
            )
    flat_shared: list[dict] = []
    for edge_records in shared_by_edge:
        for record in edge_records:
            if record is None:
                raise RuntimeError("missing shared PIR record")
            flat_shared.append(record)
    return flat_shared, plaintext_by_edge, edge_requests


def _write_mpspdz_instance(
    shared_response: list[dict],
    instance_dir: Path,
    *,
    record_count: int,
    records_per_edge: int,
    record_size: int,
    logical_record_size: int,
    page_capacity: int,
    edge_cap: int,
    party_count: int,
    share_modulus: int,
    topk: int,
) -> None:
    player_dir = instance_dir / "Player-Data"
    player_dir.mkdir(parents=True, exist_ok=True)
    program = TEMPLATE.read_text().format(
        record_count=record_count,
        records_per_edge=records_per_edge,
        record_size=record_size,
        logical_record_size=logical_record_size,
        page_capacity=page_capacity,
        edge_cap=edge_cap,
        candidate_total=edge_cap if record_count == 1 else edge_cap * edge_cap,
        party_count=party_count,
        share_modulus=share_modulus,
        top_k=topk,
    )
    (instance_dir / "secure_numeric_pir_record_topk.mpc").write_text(program)
    per_party_lines = [[] for _ in range(party_count)]
    for record in shared_response:
        shares = record["record_slot_shares"]
        if len(shares) != party_count:
            raise ValueError("PIR share party count does not match MP-SPDZ party count")
        offset = int(record.get("fedkg_page_offset", 0))
        offset_shares = _share_public_value(offset, party_count, share_modulus)
        for party in range(party_count):
            if len(shares[party]) != record_size:
                raise ValueError("PIR record share width does not match record_size")
            per_party_lines[party].append(str(offset_shares[party]))
            per_party_lines[party].extend(str(value) for value in shares[party])
    for party, lines in enumerate(per_party_lines):
        (player_dir / f"Input-P{party}-0").write_text("\n".join(lines) + "\n")


def _run_mpspdz(
    instance_dir: Path,
    mp_spdz_home: Path,
    party_count: int,
    timeout: float,
    *,
    protocol: str = "semi",
) -> str:
    program_name = "secure_numeric_pir_record_topk"
    script_by_protocol = {
        "semi": "semi.sh",
        "atlas": "atlas.sh",
    }
    script_name = script_by_protocol.get(protocol)
    if script_name is None:
        raise ValueError(f"unsupported MP-SPDZ protocol: {protocol}")
    source_dir = mp_spdz_home / "Programs" / "Source"
    player_dir = mp_spdz_home / "Player-Data"
    source_dir.mkdir(parents=True, exist_ok=True)
    player_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(instance_dir / f"{program_name}.mpc", source_dir / f"{program_name}.mpc")
    for input_file in (instance_dir / "Player-Data").glob("Input-P*-0"):
        shutil.copy(input_file, player_dir / input_file.name)
    env = os.environ.copy()
    env["PLAYERS"] = str(party_count)
    compile_run = subprocess.run(
        ["./compile.py", program_name],
        cwd=mp_spdz_home,
        env=env,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if compile_run.returncode != 0:
        raise RuntimeError(compile_run.stderr.strip() or compile_run.stdout.strip())
    run = subprocess.run(
        [f"Scripts/{script_name}", program_name],
        cwd=mp_spdz_home,
        env=env,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if run.returncode != 0:
        raise RuntimeError(run.stderr.strip() or run.stdout.strip())
    (instance_dir / "mp_spdz_output.txt").write_text(run.stdout)
    return run.stdout


def _parse_selected_slots(output: str, sentinel: int) -> list[int]:
    slots = []
    in_table = False
    for line in output.splitlines():
        if line.strip() == "rank selected_numeric_path_slot":
            in_table = True
            continue
        if not in_table:
            continue
        match = SELECTED_RE.match(line)
        if not match:
            if slots:
                break
            continue
        slot = int(match.group(2))
        if slot != sentinel:
            slots.append(slot)
    return slots


def _decode_selected_paths(
    selected_slots: list[int],
    records_by_edge: list[list[list[int]]],
    edge_cap: int,
    records_per_edge: int,
    id_map: dict,
) -> list[dict]:
    out = []
    effective_records = [_combine_plain_records(records) for records in records_by_edge]
    for rank, slot in enumerate(selected_slots):
        if len(records_by_edge) == 1:
            edge = _edge_at(effective_records[0], slot)
            if edge is not None:
                out.append(
                    {
                        "rank": rank,
                        "slot": slot,
                        "edge_slot": slot,
                        "edges": [_display_edge(edge, id_map)],
                    }
                )
            continue
        left_slot = slot // edge_cap
        right_slot = slot % edge_cap
        left = _edge_at(effective_records[0], left_slot)
        right = _edge_at(effective_records[1], right_slot)
        if left is not None and right is not None:
            out.append(
                {
                    "rank": rank,
                    "pair_slot": slot,
                    "left_edge_slot": left_slot,
                    "right_edge_slot": right_slot,
                    "edges": [_display_edge(left, id_map), _display_edge(right, id_map)],
                }
            )
    return out


def _combine_plain_records(records: list[list[int]]) -> list[int]:
    if not records:
        return []
    width = len(records[0])
    combined = [0] * width
    for record in records:
        if len(record) != width:
            raise ValueError("all records must have equal width")
        for index, value in enumerate(record):
            combined[index] += value
    return combined


def _logical_record_at(page: list[int], offset: int, logical_record_size: int) -> list[int]:
    start = offset * logical_record_size
    end = start + logical_record_size
    return page[start:end]


def _slice_shared_record(record: dict, offset: int, logical_record_size: int) -> dict:
    start = offset * logical_record_size
    end = start + logical_record_size
    return {
        **record,
        "record_slot_shares": [party_share[start:end] for party_share in record["record_slot_shares"]],
        "fedkg_page_offset": 0,
    }


def _share_public_value(value: int, party_count: int, modulus: int) -> list[int]:
    if party_count < 1:
        raise ValueError("party_count must be positive")
    shares = [secrets.randbelow(modulus) for _ in range(party_count - 1)]
    final = (value - sum(shares)) % modulus
    return shares + [final]


def _edge_at(record: list[int], slot: int) -> list[int] | None:
    if slot < 0 or slot >= record[0]:
        return None
    start = 1 + slot * 3
    return record[start : start + 3]


def _display_edge(edge: list[int], id_map: dict) -> list[str]:
    displays = id_map.get("int_to_display", {})
    hmacs = id_map.get("int_to_hmac", {})
    return [displays.get(str(value), hmacs.get(str(value), str(value))) for value in edge]


def _parse_metrics(output: str) -> dict:
    time_match = TIME_RE.search(output)
    party_data_match = PARTY_DATA_RE.search(output)
    global_data_match = GLOBAL_DATA_RE.search(output)
    return {
        "mpc_time_seconds": float(time_match.group(1)) if time_match else None,
        "party0_data_mb": float(party_data_match.group(1)) if party_data_match else None,
        "rounds": int(party_data_match.group(2)) if party_data_match else None,
        "global_data_mb": float(global_data_match.group(1)) if global_data_match else None,
    }


if __name__ == "__main__":
    raise SystemExit(main())
