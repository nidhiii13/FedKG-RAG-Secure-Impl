#!/usr/bin/env python3
"""Collect every CWQ cleartext run summary into one comparison table."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    rows = []
    for summary_path in sorted(ROOT.glob("results/cwq_cleartext_*/summary.json")):
        s = json.loads(summary_path.read_text(encoding="utf-8"))
        f = s["fixture"]
        rows.append({
            "run": summary_path.parent.name,
            "questions": s["questions_sampled"],
            "bound": s["bound"],
            "top_k": s["top_k"],
            "cap": s["neighbourhood_cap"],
            "owners": f["owners"],
            "partition": f["partition"],
            "hit_rate": round(s["evidence_hit_rate"], 4),
            "ci95": [round(x, 4) for x in s["evidence_hit_ci95"]],
            "plaintext_same_bound": round(s["plaintext_same_bound"], 4),
            "ceiling": round(s["fixture_ceiling_unclipped"], 4),
            "paged_minus_plaintext_pts":
                round(-s["paged_vs_plaintext_same_bound_points"], 3),
            "empty": s["empty_retrievals"],
            "multi_owner_q": s.get("questions_with_multi_owner_evidence"),
            "cross_owner_chain_q": s.get("questions_with_cross_owner_chain"),
            "owner_skew": round(f["owner_key_skew"], 3) if f.get("owner_key_skew") else None,
            "spanning_keys": f.get("adjacency_keys_spanning_multiple_owners"),
            "fixture_entities": f["entities"],
            "fixture_relations": f["relations"],
            "edges_kept": f["edges_kept"],
            "layout_s": round(s["layout_preparation_seconds"], 1),
            "retrieval_s": round(s["retrieval_seconds"], 2),
            "wall_s": round(s["total_wall_seconds"], 1),
        })
    out = ROOT / "results" / "cwq_runs_table.json"
    out.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    header = ("run questions bound top_k cap owners partition hit_rate "
              "plaintext ceiling empty").split()
    print(" | ".join(header))
    for row in rows:
        print(" | ".join(str(row[k]) for k in (
            "run", "questions", "bound", "top_k", "cap", "owners", "partition",
            "hit_rate", "plaintext_same_bound", "ceiling", "empty")))
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
