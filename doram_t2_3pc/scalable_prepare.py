from __future__ import annotations

import argparse
from pathlib import Path

from .config import EDGE_FIELDS, PublicConfig, SCALABLE_FIELD_PRIME
from .io import read_json, write_private_lines
from .prepare import _validate_shard
from .sharing import SERVER_COUNT


def _require_scalable_config(config: PublicConfig) -> None:
    if config.field_prime != SCALABLE_FIELD_PRIME:
        raise ValueError("scalable preparation requires field_prime=2^127-1")


def assemble_setup_input(
    config: PublicConfig,
    server: int,
    owner_shards: list[str | Path],
    output_path: str | Path,
) -> Path:
    """Assemble the one-time graph-only input for one computation server."""
    _require_scalable_config(config)
    if server not in range(SERVER_COUNT):
        raise ValueError("server must be 0, 1, or 2")
    if len(owner_shards) != len(config.owners):
        raise ValueError(f"expected exactly {len(config.owners)} owner shards")

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

    combined: list[int] = []
    width = config.fanout_per_owner * len(EDGE_FIELDS)
    for entity in range(config.entity_count):
        start = entity * width
        for owner_index in range(len(config.owners)):
            combined.extend(by_index[owner_index][start : start + width])
    if len(combined) != config.entity_count * config.block_edges * len(EDGE_FIELDS):
        raise AssertionError("internal scalable setup-input length mismatch")
    destination = Path(output_path)
    write_private_lines(destination, combined)
    return destination


def assemble_query_input(
    config: PublicConfig,
    server: int,
    query_shard: str | Path,
    output_path: str | Path,
) -> Path:
    """Assemble the three-value online query input for one server."""
    _require_scalable_config(config)
    if server not in range(SERVER_COUNT):
        raise ValueError("server must be 0, 1, or 2")
    values = _validate_shard(
        read_json(query_shard),
        kind="query-shard",
        config=config,
        server=server,
        count=3,
    )
    destination = Path(output_path)
    write_private_lines(destination, values)
    return destination


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Assemble separate persistent-DORAM setup and query inputs"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    setup = sub.add_parser("setup")
    setup.add_argument("--config", required=True)
    setup.add_argument("--server", required=True, type=int)
    setup.add_argument("--owner-shard", action="append", required=True)
    setup.add_argument("--output", required=True)
    query = sub.add_parser("query")
    query.add_argument("--config", required=True)
    query.add_argument("--server", required=True, type=int)
    query.add_argument("--query-shard", required=True)
    query.add_argument("--output", required=True)
    args = parser.parse_args()
    config = PublicConfig.load(args.config)
    if args.command == "setup":
        assemble_setup_input(config, args.server, args.owner_shard, args.output)
    else:
        assemble_query_input(
            config, args.server, args.query_shard, args.output
        )


if __name__ == "__main__":
    main()
