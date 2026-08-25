#!/usr/bin/env python3
"""Client-side reconstruction and exact-oracle check for a prepared instance."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from doram_t2_3pc.decode_batch import decode_batch_logs
from doram_t2_3pc.relation_pages import RelationPageConfig


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--instance-dir", required=True, type=Path)
    parser.add_argument(
        "--config",
        type=Path,
        help="public config; defaults to INSTANCE/config.json or manifest config_source",
    )
    parser.add_argument("--server-log", action="append", required=True, type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    instance = args.instance_dir.resolve()
    manifest = json.loads((instance / "manifest.json").read_text(encoding="utf-8"))
    config_path = args.config
    if config_path is None:
        local = instance / "config.json"
        if local.is_file():
            config_path = local
        elif manifest.get("config_source"):
            config_path = Path(str(manifest["config_source"]))
        else:
            raise ValueError("no public config supplied or recorded in manifest")
    config = RelationPageConfig.load(config_path)
    query_count = int(manifest["epoch_authorization"]["query_count"])
    reconstructed = decode_batch_logs(
        config.base, query_count, list(args.server_log)
    )
    expected = manifest.get("expected")
    report = {
        "program": manifest["program"],
        "query_count": query_count,
        "fields_compared": query_count * config.base.top_k * 4,
        "exact_match": reconstructed == expected,
        "expected": expected,
        "reconstructed": reconstructed,
    }
    rendered = json.dumps(report, indent=2) + "\n"
    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if report["exact_match"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
