from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from .config import EDGE_FIELDS, FORMAT_VERSION, PublicConfig
from .io import read_json, write_private_json, write_private_lines
from .sharing import SERVER_COUNT, share_vector


def _bounded_int(value: Any, name: str, upper_exclusive: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if not 0 <= value < upper_exclusive:
        raise ValueError(f"{name} must be in [0, {upper_exclusive})")
    return value


def owner_plain_vector(config: PublicConfig, owner: str, edges: list[dict[str, Any]]) -> list[int]:
    if owner not in config.owners:
        raise ValueError(f"unknown owner {owner!r}")
    buckets: list[list[tuple[int, int, int, int, int]]] = [
        [] for _ in range(config.entity_count)
    ]
    for row_number, edge in enumerate(edges, start=1):
        if set(edge) != {"source", "relation", "target", "evidence", "score"}:
            raise ValueError(f"edge {row_number} must contain exactly source/relation/target/evidence/score")
        try:
            source = config.entities[edge["source"]]
            target = config.entities[edge["target"]]
            relation = config.relations[edge["relation"]]
        except (KeyError, TypeError) as exc:
            raise ValueError(f"edge {row_number} uses an unknown entity or relation") from exc
        evidence = _bounded_int(edge["evidence"], f"edge {row_number} evidence", 1 << config.evidence_bits)
        if evidence == 0:
            raise ValueError("evidence handle zero is reserved for padding")
        score = _bounded_int(edge["score"], f"edge {row_number} score", 1 << config.score_bits)
        buckets[source].append((target, relation, evidence, score, 1))

    zero = (0, 0, 0, 0, 0)
    flat: list[int] = []
    for slot, bucket in enumerate(buckets):
        if len(bucket) > config.fanout_per_owner:
            raise ValueError(
                f"owner {owner!r} has {len(bucket)} edges at entity slot {slot}; "
                f"public bound is {config.fanout_per_owner}"
            )
        padded = bucket + [zero] * (config.fanout_per_owner - len(bucket))
        for edge in padded:
            flat.extend(edge)
    if len(flat) != config.owner_value_count:
        raise AssertionError("internal owner-vector length mismatch")
    return flat


def create_owner_shards(
    config: PublicConfig, owner: str, edge_path: str | Path, output_dir: str | Path
) -> list[Path]:
    raw = read_json(edge_path)
    if not isinstance(raw, list):
        raise ValueError("owner edge file must be a JSON list")
    vectors = share_vector(
        owner_plain_vector(config, owner, raw), modulus=config.field_prime
    )
    outputs: list[Path] = []
    for server, values in enumerate(vectors):
        document = {
            "version": FORMAT_VERSION,
            "kind": "owner-shard",
            "config_digest": config.digest,
            "owner": owner,
            "owner_index": config.owners.index(owner),
            "server": server,
            "values": values,
        }
        path = Path(output_dir) / f"owner-{config.owners.index(owner)}-to-server-{server}.json"
        write_private_json(path, document)
        outputs.append(path)
    return outputs


def create_query_shards(
    config: PublicConfig, query_path: str | Path, output_dir: str | Path
) -> list[Path]:
    query = read_json(query_path)
    if not isinstance(query, dict) or set(query) != {"source", "relation_1", "relation_2"}:
        raise ValueError("query must contain exactly source/relation_1/relation_2")
    try:
        values = [
            config.entities[query["source"]],
            config.relations[query["relation_1"]],
            config.relations[query["relation_2"]],
        ]
    except (KeyError, TypeError) as exc:
        raise ValueError("query uses an unknown entity or relation") from exc
    vectors = share_vector(values, modulus=config.field_prime)
    outputs: list[Path] = []
    for server, shares in enumerate(vectors):
        document = {
            "version": FORMAT_VERSION,
            "kind": "query-shard",
            "config_digest": config.digest,
            "server": server,
            "values": shares,
        }
        path = Path(output_dir) / f"query-to-server-{server}.json"
        write_private_json(path, document)
        outputs.append(path)
    return outputs


def _validate_shard(
    document: Any, *, kind: str, config: PublicConfig, server: int, count: int
) -> list[int]:
    if not isinstance(document, dict):
        raise ValueError("shard must be a JSON object")
    if document.get("version") != FORMAT_VERSION or document.get("kind") != kind:
        raise ValueError("shard version or kind mismatch")
    if document.get("config_digest") != config.digest or document.get("server") != server:
        raise ValueError("shard belongs to a different configuration or server")
    values = document.get("values")
    if not isinstance(values, list) or len(values) != count:
        raise ValueError(f"shard must contain exactly {count} values")
    if any(
        isinstance(x, bool)
        or not isinstance(x, int)
        or not 0 <= x < config.field_prime
        for x in values
    ):
        raise ValueError("shard contains a non-canonical field element")
    return values


def assemble_server_input(
    config: PublicConfig,
    server: int,
    query_shard: str | Path,
    owner_shards: list[str | Path],
    output_path: str | Path,
) -> Path:
    if server not in range(SERVER_COUNT):
        raise ValueError("server must be 0, 1, or 2")
    if len(owner_shards) != len(config.owners):
        raise ValueError(f"expected exactly {len(config.owners)} owner shards")
    query_values = _validate_shard(
        read_json(query_shard), kind="query-shard", config=config, server=server, count=3
    )
    by_index: dict[int, list[int]] = {}
    for path in owner_shards:
        document = read_json(path)
        values = _validate_shard(
            document,
            kind="owner-shard",
            config=config,
            server=server,
            count=config.owner_value_count,
        )
        index = document.get("owner_index")
        owner = document.get("owner")
        if not isinstance(index, int) or index not in range(len(config.owners)):
            raise ValueError("invalid owner index")
        if owner != config.owners[index] or index in by_index:
            raise ValueError("owner identity mismatch or duplicate owner shard")
        by_index[index] = values
    if set(by_index) != set(range(len(config.owners))):
        raise ValueError("owner shard set is incomplete")

    # Program consumption order is query, then entity, owner, local edge, field.
    combined = list(query_values)
    width = config.fanout_per_owner * len(EDGE_FIELDS)
    for entity in range(config.entity_count):
        start = entity * width
        for owner_index in range(len(config.owners)):
            combined.extend(by_index[owner_index][start : start + width])
    destination = Path(output_path)
    write_private_lines(destination, combined)
    return destination


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    owner = sub.add_parser("owner", help="create one data owner's three outgoing shards")
    owner.add_argument("--config", required=True)
    owner.add_argument("--owner", required=True)
    owner.add_argument("--edges", required=True)
    owner.add_argument("--output-dir", required=True)
    query = sub.add_parser("query", help="create the query client's three outgoing shards")
    query.add_argument("--config", required=True)
    query.add_argument("--query", required=True)
    query.add_argument("--output-dir", required=True)
    assemble = sub.add_parser("assemble", help="assemble one server's private MP-SPDZ input")
    assemble.add_argument("--config", required=True)
    assemble.add_argument("--server", required=True, type=int)
    assemble.add_argument("--query-shard", required=True)
    assemble.add_argument("--owner-shard", action="append", required=True)
    assemble.add_argument("--output", required=True)
    return parser


def main() -> None:
    args = _parser().parse_args()
    config = PublicConfig.load(args.config)
    if args.command == "owner":
        create_owner_shards(config, args.owner, args.edges, args.output_dir)
    elif args.command == "query":
        create_query_shards(config, args.query, args.output_dir)
    else:
        assemble_server_input(
            config, args.server, args.query_shard, args.owner_shard, args.output
        )


if __name__ == "__main__":
    main()
