#!/usr/bin/env python3
"""Profile ComplexWebQuestions 1.1 for dependent two-hop compatibility.

The compatible class is decided by parsing the **gold SPARQL** shipped with the
official CWQ release -- never by consulting gold answers.  A question is strict
two-hop compatible when its WHERE clause is exactly two triple patterns forming
one dependent chain

    anchor --relation_1--> ?intermediate --relation_2--> ?x

in any edge orientation, with a single grounded anchor entity, no additional
constraint triples, no non-boilerplate FILTER, no EXISTS/UNION/OPTIONAL/MINUS,
and no ORDER BY / LIMIT tail.  Everything else is rejected with an explicit
reason.  In the RoG-CWQ graph snapshot one hop is one edge, so CVT-mediated
patterns are first-class two-hop chains here.

Anchors in SPARQL are Freebase MIDs while the RoG-CWQ graphs carry surface
names, so the anchor is mapped through the row's public topic-entity annotation
(`q_entity`), disambiguated -- when several topic entities exist -- by which
one carries an edge with `relation_1` in the required orientation.  That uses
the query structure only; answers are never consulted.

Outputs (per requirements):
    <out>/compatibility_summary.json
    <out>/twohop_compatible.jsonl
    <out>/rejected_examples.jsonl
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

TRIPLE = re.compile(
    r"^(\?\w+|ns:[\w.\$_-]+)\s+ns:([\w.]+)\s+"
    r"(\?\w+|ns:[\w.\$_-]+|\"[^\"]*\"(?:@[\w-]+|\^\^\S+)?)\s*\.?\s*$"
)
BOILERPLATE_FILTERS = (
    re.compile(r"^FILTER \(\?x != (\?\w+|ns:[\w.\$_-]+)\)$"),
    re.compile(r"^FILTER \(!isLiteral\(\?x\) OR lang\(\?x\) = '' "
               r"OR langMatches\(lang\(\?x\), 'en'\)\)$"),
)


def parse_sparql(sparql: str) -> dict[str, Any]:
    """Decompose one CWQ SPARQL string into triples plus structural flags."""

    flags: set[str] = set()
    triples: list[tuple[str, str, str]] = []
    filters: list[str] = []
    depth_extra = 0  # brace depth inside FILTER(EXISTS ...) blocks
    for raw in sparql.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            if line.startswith("#MANUAL"):
                flags.add("manual_sparql")
            continue
        if depth_extra > 0:
            depth_extra += line.count("{") - line.count("}")
            continue
        upper = line.upper()
        if "EXISTS" in upper:
            flags.add("exists")
            depth_extra = line.count("{") - line.count("}")
            continue
        if any(tok in upper for tok in ("UNION", "OPTIONAL", "MINUS")):
            flags.add("union_optional_minus")
            continue
        if upper.startswith(("PREFIX", "WHERE", "{", "}")):
            continue
        if upper.startswith("SELECT"):
            if "?x" not in line:
                flags.add("select_not_x")
            continue
        if upper.startswith(("ORDER", "LIMIT", "OFFSET")):
            flags.add("order_limit")
            continue
        if upper.startswith("FILTER"):
            if any(p.match(line) for p in BOILERPLATE_FILTERS):
                continue
            filters.append(line)
            continue
        match = TRIPLE.match(line)
        if match:
            triples.append((match.group(1), match.group(2), match.group(3)))
        else:
            flags.add("unparsed_line")
    return {"triples": triples, "filters": filters, "flags": flags}


def _grounded(term: str) -> bool:
    return term.startswith("ns:")


def _variable(term: str) -> bool:
    return term.startswith("?")


def extract_chain(parsed: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    """Classify the pattern; return (category, chain-or-None).

    ``strict_two_hop`` requires: exactly two triples, no flags, no filters, one
    grounded term total, chain anchor -> ?mid -> ?x.  The chain records each
    hop's relation with an ``_inverse`` suffix when the triple points toward
    the anchor, matching how the evaluation adjacency materialises inverses.
    """

    flags, triples, filters = parsed["flags"], parsed["triples"], parsed["filters"]
    if "manual_sparql" in flags or "unparsed_line" in flags:
        return ("unparsed_manual_sparql", None)
    if "union_optional_minus" in flags:
        return ("union_optional_minus", None)
    if "select_not_x" in flags:
        return ("select_not_x", None)

    grounded_terms = [t for s, _, o in triples for t in (s, o) if _grounded(t)]
    literals = [o for _, _, o in triples if not _grounded(o) and not _variable(o)]
    n = len(triples)

    if n == 0:
        return ("no_triples", None)

    def chain_shape() -> dict[str, Any] | None:
        """Two triples forming anchor -> ?mid -> ?x, else None."""
        if n != 2 or len(grounded_terms) != 1 or literals:
            return None
        anchor = grounded_terms[0]
        for first, second in (triples, triples[::-1]):
            ends1 = (first[0], first[2])
            if anchor not in ends1:
                continue
            if first[0] == anchor and _variable(first[2]):
                relation_1, mid = first[1], first[2]
            elif first[2] == anchor and _variable(first[0]):
                relation_1, mid = first[1] + "_inverse", first[0]
            else:
                continue
            if mid == "?x":
                continue
            if second[0] == mid and second[2] == "?x":
                relation_2 = second[1]
            elif second[2] == mid and second[0] == "?x":
                relation_2 = second[1] + "_inverse"
            else:
                continue
            return {
                "anchor_mid": anchor[len("ns:"):],
                "relation_1": relation_1,
                "relation_2": relation_2,
            }
        return None

    chain = chain_shape()
    if "order_limit" in flags or "exists" in flags:
        return ("order_limit_or_temporal", None)
    if filters:
        return ("unsupported_filter", None)
    if n == 1:
        return ("one_hop", None)
    if chain is not None:
        return ("strict_two_hop", chain)
    if n == 2:
        return ("two_triples_not_dependent_chain", None)
    # n >= 3: distinguish longer chains from trees/joins only for reporting.
    if len(set(grounded_terms)) > 1:
        return (f"multi_anchor_join_{n}_triples", None)
    return (f"chain_or_tree_{n}_triples", None)


def load_rog(path: Path) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                row = json.loads(line)
                rows[str(row["id"])] = row
    return rows


def map_anchor(chain: dict[str, Any], rog_row: dict[str, Any]) -> tuple[str | None, str]:
    """Map the SPARQL anchor MID to a RoG graph node, answer-independently.

    Preference order: the MID itself when it is a graph node; otherwise the
    unique topic entity (`q_entity`) carrying an edge whose relation matches
    ``relation_1`` in the required orientation.
    """

    graph = rog_row.get("graph", [])
    mid = chain["anchor_mid"]
    relation_1 = chain["relation_1"]
    inverse = relation_1.endswith("_inverse")
    base_relation = relation_1[:-len("_inverse")] if inverse else relation_1

    nodes = set()
    outgoing: dict[str, set[str]] = {}
    incoming: dict[str, set[str]] = {}
    for head, relation, tail in graph:
        head, relation, tail = str(head), str(relation), str(tail)
        nodes.add(head)
        nodes.add(tail)
        outgoing.setdefault(head, set()).add(relation)
        incoming.setdefault(tail, set()).add(relation)
    if mid in nodes:
        return mid, "anchor_mid_in_graph"
    candidates = sorted({str(e) for e in rog_row.get("q_entity", [])} & nodes)
    if not candidates:
        return None, "no_topic_entity_in_graph"
    matching = [
        name for name in candidates
        if base_relation in (incoming if inverse else outgoing).get(name, set())
    ]
    if len(matching) == 1:
        return matching[0], "unique_topic_entity_with_relation_1"
    if len(matching) > 1:
        return None, "ambiguous_topic_entities_with_relation_1"
    if len(candidates) == 1:
        return candidates[0], "single_topic_entity_without_relation_1_edge"
    return None, "no_topic_entity_carries_relation_1"


def profile_split(
    split: str, official_path: Path, rog_path: Path,
    compatible_log, rejected_log,
) -> dict[str, Any]:
    official = json.loads(official_path.read_text(encoding="utf-8"))
    rog = load_rog(rog_path)
    categories: Counter[str] = Counter()
    anchor_outcomes: Counter[str] = Counter()
    compatible = 0
    seen_ids: set[str] = set()
    for record in official:
        qid = str(record["ID"])
        if qid in seen_ids:
            categories["duplicate_id"] += 1
            continue
        seen_ids.add(qid)
        category, chain = extract_chain(parse_sparql(record["sparql"]))
        rog_row = rog.get(qid)
        if rog_row is None:
            category, chain = "missing_rog_row", None
        if category == "strict_two_hop":
            anchor, how = map_anchor(chain, rog_row)
            anchor_outcomes[how] += 1
            if anchor is None:
                category = f"anchor_unmapped:{how}"
            else:
                compatible += 1
                compatible_log.write(json.dumps({
                    "id": qid,
                    "split": split,
                    "question": record["question"],
                    "compositionality_type": record["compositionality_type"],
                    "anchor": anchor,
                    "anchor_mid": chain["anchor_mid"],
                    "anchor_mapping": how,
                    "relation_1": chain["relation_1"],
                    "relation_2": chain["relation_2"],
                    "query_graph": [
                        [anchor, chain["relation_1"], "UNKNOWN"],
                        ["UNKNOWN", chain["relation_2"], "ANSWER"],
                    ],
                    "groundtruths": sorted(
                        {str(a) for a in rog_row.get("answer", [])}
                        | {str(a) for a in rog_row.get("a_entity", [])}
                    ),
                    "path_source": "gold SPARQL (answer-independent)",
                }, ensure_ascii=False) + "\n")
        if category != "strict_two_hop":
            rejected_log.write(json.dumps({
                "id": qid, "split": split, "reason": category,
                "compositionality_type": record.get("compositionality_type"),
            }, ensure_ascii=False) + "\n")
        categories[category] += 1
    return {
        "split": split,
        "official_file": str(official_path),
        "rog_file": str(rog_path),
        "questions_total": len(official),
        "unique_ids": len(seen_ids),
        "strict_two_hop_compatible": compatible,
        "categories": dict(categories.most_common()),
        "anchor_mapping_outcomes": dict(anchor_outcomes.most_common()),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, default=ROOT / "data/cwq/raw")
    parser.add_argument("--out", type=Path, default=ROOT / "data/cwq")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    started = time.time()
    splits = [
        ("test", args.raw / "ComplexWebQuestions_test.json",
         args.raw / "rog_cwq_test.jsonl"),
        ("validation", args.raw / "ComplexWebQuestions_dev.json",
         args.raw / "rog_cwq_validation.jsonl"),
    ]
    summaries = []
    with (args.out / "twohop_compatible.jsonl").open("w", encoding="utf-8") as ok, \
         (args.out / "rejected_examples.jsonl").open("w", encoding="utf-8") as bad:
        for split, official_path, rog_path in splits:
            summary = profile_split(split, official_path, rog_path, ok, bad)
            summaries.append(summary)
            print(f"{split}: {summary['strict_two_hop_compatible']} strict two-hop "
                  f"of {summary['questions_total']} "
                  f"({dict(list(summary['categories'].items())[:4])} ...)")
    total = sum(s["questions_total"] for s in summaries)
    compatible = sum(s["strict_two_hop_compatible"] for s in summaries)
    payload = {
        "dataset": "ComplexWebQuestions 1.1 + RoG-CWQ graph snapshot",
        "path_source": "gold SPARQL parsing; answers never consulted for paths",
        "held_out_splits_profiled": [s["split"] for s in summaries],
        "questions_total": total,
        "strict_two_hop_compatible": compatible,
        "splits": summaries,
        "profiling_seconds": round(time.time() - started, 2),
    }
    (args.out / "compatibility_summary.json").write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )
    print(f"combined held-out strict two-hop compatible: {compatible}/{total}")
    print(f"wrote {args.out / 'compatibility_summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
