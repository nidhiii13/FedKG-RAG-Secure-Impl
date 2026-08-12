from __future__ import annotations

import argparse

from .config import PublicConfig
from .packed import (
    assemble_packed_batch_from_paths,
    create_packed_owner_shards,
    create_packed_query_batch_shards,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prepare private inputs for the packed batch DORAM"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    owner = sub.add_parser("owner")
    owner.add_argument("--config", required=True)
    owner.add_argument("--owner", required=True)
    owner.add_argument("--edges", required=True)
    owner.add_argument("--output-dir", required=True)

    query = sub.add_parser("query-batch")
    query.add_argument("--config", required=True)
    query.add_argument("--queries", required=True)
    query.add_argument("--output-dir", required=True)

    assemble = sub.add_parser("assemble")
    assemble.add_argument("--config", required=True)
    assemble.add_argument("--server", required=True, type=int)
    assemble.add_argument("--query-count", required=True, type=int)
    assemble.add_argument("--query-shard", required=True)
    assemble.add_argument("--owner-shard", action="append", required=True)
    assemble.add_argument("--output", required=True)

    args = parser.parse_args()
    config = PublicConfig.load(args.config)
    if args.command == "owner":
        create_packed_owner_shards(
            config, args.owner, args.edges, args.output_dir
        )
    elif args.command == "query-batch":
        create_packed_query_batch_shards(config, args.queries, args.output_dir)
    else:
        assemble_packed_batch_from_paths(
            config,
            args.server,
            args.query_count,
            args.query_shard,
            args.owner_shard,
            args.output,
        )


if __name__ == "__main__":
    main()
