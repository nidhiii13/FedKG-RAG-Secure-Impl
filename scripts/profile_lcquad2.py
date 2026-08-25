#!/usr/bin/env python3
"""Download and profile LC-QuAD 2.0 for the two-hop KG retrieval backend.

LC-QuAD 2.0 is useful as a heterogeneous QA benchmark, but it is not a drop-in
replacement for MetaQA/WebQSP in this repository: the Hugging Face copy ships
questions and SPARQL queries, not a local Wikidata/DBpedia graph snapshot or
answer cache. This script therefore performs the honest first step:

* download or load the dataset;
* parse the SPARQL query patterns;
* keep examples that are exactly one dependent two-hop path from a concrete
  entity to the selected answer variable;
* export those examples as SimGRAG-style query graphs for later fixture
  materialisation.

The output is a compatibility report, not a retrieval-quality result.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import urllib.request
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any


HF_DATA_ZIP = "https://huggingface.co/datasets/mohnish/lc_quad/resolve/main/data.zip"
DEFAULT_OUT = Path("data/lc_quad2")
VARIABLE_RE = re.compile(r"\?[A-Za-z_][A-Za-z0-9_]*")
TRIPLE_RE = re.compile(r"^(\S+)\s+(\S+)\s+(.+?)$")


def _read_json_rows(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if isinstance(payload, dict):
        for key in ("data", "rows", "train", "test"):
            value = payload.get(key)
            if isinstance(value, list):
                return [row for row in value if isinstance(row, dict)]
    raise ValueError(f"cannot find a list of rows in {path}")


def _read_jsonl_rows(path: Path) -> list[dict[str, Any]]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            if isinstance(row, dict):
                rows.append(row)
    return rows


def _read_csv_rows(path: Path) -> list[dict[str, Any]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _load_rows_from_file(path: Path) -> list[dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix == ".json":
        return _read_json_rows(path)
    if suffix == ".jsonl":
        return _read_jsonl_rows(path)
    if suffix == ".csv":
        return _read_csv_rows(path)
    raise ValueError(f"unsupported dataset file type: {path}")


def download_dataset(out: Path, force: bool) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    archive = out / "data.zip"
    if force or not archive.exists():
        print(f"downloading {HF_DATA_ZIP}")
        urllib.request.urlretrieve(HF_DATA_ZIP, archive)  # noqa: S310
    extract_dir = out / "raw"
    extract_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as zipped:
        zipped.extractall(extract_dir)
    return extract_dir


def find_dataset_files(root: Path) -> list[Path]:
    allowed = {".json", ".jsonl", ".csv"}
    return sorted(path for path in root.rglob("*") if path.suffix.lower() in allowed)


def load_rows(root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    files = find_dataset_files(root)
    rows: list[dict[str, Any]] = []
    used: list[str] = []
    for path in files:
        try:
            loaded = _load_rows_from_file(path)
        except Exception as exc:  # noqa: BLE001
            print(f"skipping {path}: {type(exc).__name__}: {exc}", file=sys.stderr)
            continue
        rows.extend(loaded)
        used.append(str(path))
    if not rows:
        raise ValueError(
            f"no JSON/JSONL/CSV dataset rows found under {root}; files were: "
            + ", ".join(str(path) for path in root.rglob("*") if path.is_file())
        )
    return rows, used


def strip_wrapping_quotes(value: Any) -> str:
    text = "" if value is None else str(value).strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        return text[1:-1].strip()
    return text


def selected_variable(sparql: str) -> str | None:
    match = re.search(r"\bselect\b\s+(?:distinct\s+)?(.+?)\bwhere\b", sparql, re.I | re.S)
    if not match:
        return None
    variables = VARIABLE_RE.findall(match.group(1))
    return variables[0] if variables else None


def where_body(sparql: str) -> str | None:
    start = sparql.find("{")
    end = sparql.rfind("}")
    if start < 0 or end <= start:
        return None
    return sparql[start + 1 : end]


def normalise_statement(statement: str) -> str:
    statement = re.sub(r"#.*$", "", statement).strip()
    statement = re.sub(r"\s+", " ", statement)
    return statement


def split_statements(body: str) -> list[str]:
    # LC-QuAD queries are simple enough that splitting on " . " is reliable for
    # the compatibility filter. We reject anything with nested SPARQL constructs.
    statements = []
    for chunk in re.split(r"\s+\.\s+", body):
        chunk = normalise_statement(chunk.strip().strip("."))
        if chunk:
            statements.append(chunk)
    return statements


def is_variable(term: str) -> bool:
    return term.startswith("?")


def parse_triples(sparql: str) -> tuple[list[tuple[str, str, str]], Counter[str]]:
    body = where_body(sparql)
    reasons: Counter[str] = Counter()
    if body is None:
        reasons["no_where_body"] += 1
        return [], reasons
    triples = []
    for statement in split_statements(body):
        lowered = statement.lower()
        if lowered.startswith(("filter", "optional", "service", "bind", "values", "union")):
            reasons["has_unsupported_sparql_construct"] += 1
            continue
        match = TRIPLE_RE.match(statement)
        if not match:
            reasons["unparsed_statement"] += 1
            continue
        head, relation, tail = (part.strip() for part in match.groups())
        if " " in tail:
            reasons["tail_contains_expression"] += 1
            continue
        triples.append((head, relation, tail))
    return triples, reasons


def orient_two_hop(
    triples: list[tuple[str, str, str]], answer_var: str
) -> tuple[list[list[str]], dict[str, str]] | None:
    if len(triples) != 2:
        return None

    def directed(triple: tuple[str, str, str], source: str):
        head, relation, tail = triple
        if head == source:
            return relation, tail
        if tail == source:
            return relation + "_inverse", head
        return None

    for first, second in (triples, triples[::-1]):
        for anchor in (first[0], first[2]):
            if is_variable(anchor):
                continue
            step = directed(first, anchor)
            if step is None:
                continue
            relation_1, middle = step
            if not is_variable(middle) or middle == answer_var:
                continue
            onward = directed(second, middle)
            if onward is None:
                continue
            relation_2, endpoint = onward
            if endpoint != answer_var:
                continue
            graph = [
                [anchor, relation_1, "UNKNOWN"],
                ["UNKNOWN", relation_2, "ANSWER"],
            ]
            metadata = {
                "source": anchor,
                "relation_1": relation_1,
                "relation_2": relation_2,
                "answer_variable": answer_var,
            }
            return graph, metadata
    return None


def profile_rows(rows: list[dict[str, Any]], out: Path, limit: int | None) -> dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    exported = out / "lcquad2_twohop_query_graphs.jsonl"
    reasons: Counter[str] = Counter()
    relation_counter: Counter[str] = Counter()
    path_core = 0
    strict = 0
    total = 0

    with exported.open("w", encoding="utf-8") as handle:
        for row in rows:
            if limit is not None and total >= limit:
                break
            total += 1
            sparql = strip_wrapping_quotes(
                row.get("sparql_wikidata") or row.get("sparql_dbpedia18") or row.get("query")
            )
            if not sparql:
                reasons["missing_sparql"] += 1
                continue
            answer_var = selected_variable(sparql)
            if answer_var is None:
                reasons["no_selected_variable"] += 1
                continue
            triples, parse_reasons = parse_triples(sparql)
            reasons.update(parse_reasons)
            oriented = orient_two_hop(triples, answer_var)
            if oriented is None:
                if len(triples) != 2:
                    reasons[f"not_two_triples:{len(triples)}"] += 1
                else:
                    reasons["two_triples_but_not_dependent_path"] += 1
                continue
            query_graph, metadata = oriented
            path_core += 1
            semantic_residual = bool(parse_reasons)
            if not semantic_residual:
                strict += 1
            relation_counter.update([metadata["relation_1"], metadata["relation_2"]])
            record = {
                "uid": row.get("uid") or row.get("_id"),
                "question": row.get("question") or row.get("corrected_question") or row.get("NNQT_question"),
                "paraphrased_question": row.get("paraphrased_question"),
                "query_graph": query_graph,
                "hops": metadata,
                "groundtruths": [],
                "sparql": sparql,
                "semantic_residual": semantic_residual,
                "residual_reasons": dict(parse_reasons),
                "note": (
                    "LC-QuAD supplies SPARQL but not local answers/KG; groundtruths "
                    "need materialisation. Rows with semantic_residual=true have a "
                    "two-hop retrieval core but extra SPARQL semantics such as filters "
                    "or qualifier constraints."
                ),
            }
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    summary = {
        "dataset": "lc_quad_2_0",
        "rows_profiled": total,
        "strict_two_hop_rows": strict,
        "strict_representable_fraction": round(strict / total, 6) if total else 0.0,
        "two_hop_core_rows": path_core,
        "two_hop_core_fraction": round(path_core / total, 6) if total else 0.0,
        "rejection_reasons": dict(reasons.most_common()),
        "top_relations": relation_counter.most_common(30),
        "exported_query_graphs": str(exported),
        "compatibility_scope": (
            "strict_two_hop_rows are pure two-triple dependent paths. "
            "two_hop_core_rows additionally include questions with a usable two-hop "
            "retrieval core plus residual SPARQL semantics. Neither is a "
            "retrieval-quality result until answers and a local KG slice are "
            "materialised."
        ),
    }
    (out / "lcquad2_compatibility_summary.json").write_text(
        json.dumps(summary, indent=1, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--input", type=Path, default=None,
                        help="Existing extracted LC-QuAD directory or JSON/JSONL/CSV file")
    parser.add_argument("--download", action="store_true",
                        help="Download data.zip from Hugging Face into --out")
    parser.add_argument("--force-download", action="store_true")
    parser.add_argument("--limit", type=int, default=None,
                        help="Profile only the first N rows")
    args = parser.parse_args()

    if args.input is not None:
        source = args.input
    elif args.download:
        source = download_dataset(args.out, args.force_download)
    else:
        source = args.out / "raw"

    if source.is_file():
        rows = _load_rows_from_file(source)
        used = [str(source)]
    else:
        rows, used = load_rows(source)

    summary = profile_rows(rows, args.out, args.limit)
    print(f"loaded {len(rows):,} rows from {len(used)} file(s)")
    for path in used:
        print(f"  {path}")
    print(f"strict two-hop rows: {summary['strict_two_hop_rows']:,}/"
          f"{summary['rows_profiled']:,} "
          f"({100*summary['strict_representable_fraction']:.2f}%)")
    print(f"two-hop retrieval-core rows: {summary['two_hop_core_rows']:,}/"
          f"{summary['rows_profiled']:,} ({100*summary['two_hop_core_fraction']:.2f}%)")
    print(f"wrote {summary['exported_query_graphs']}")
    print(f"wrote {args.out / 'lcquad2_compatibility_summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
