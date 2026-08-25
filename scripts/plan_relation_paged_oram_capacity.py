#!/usr/bin/env python3
"""Emit an auditable public-shape capacity report without compiling MPC."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from doram_t2_3pc.relation_paged_oram import (  # noqa: E402
    planned_relation_paged_oram_cost_report,
)
from doram_t2_3pc.relation_pages import RelationPageConfig  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Plan relation-paged recursive-ORAM capacity from public dimensions; "
            "this does not predict runtime or claim an execution."
        )
    )
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--query-count", required=True, type=int)
    parser.add_argument("--chi", type=int, default=256)
    parser.add_argument("--base-threshold", type=int, default=64)
    parser.add_argument("--statistical-security-bits", type=int, default=80)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    config = RelationPageConfig.load(args.config)
    report = {
        "status": "public-shape capacity estimate; not an MPC measurement",
        "config": str(args.config.resolve()),
        "config_digest": config.digest,
        "shape_options": {
            "chi": args.chi,
            "base_threshold": args.base_threshold,
            "statistical_security_bits": args.statistical_security_bits,
        },
        "capacity": planned_relation_paged_oram_cost_report(
            config,
            query_count=args.query_count,
            chi=args.chi,
            base_threshold=args.base_threshold,
            statistical_security_bits=args.statistical_security_bits,
        ),
        "interpretation": {
            "database_scaling": (
                "Tree-path work is sublinear in public directory/page-pool size."
            ),
            "batch_scaling": (
                "The current replay-hiding stash is quadratic in accesses per "
                "fresh epoch; do not extrapolate large query batches linearly."
            ),
            "privacy": (
                "All counts are functions only of public configuration and batch "
                "size; no query address, occupancy, result count, or owner edge is used."
            ),
        },
    }
    rendered = json.dumps(report, indent=2) + "\n"
    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
