#!/usr/bin/env python3
"""Batch secure frontier retrieval over SimGRAG party data.

The batch runner measures the secure retrieval/ranking path. It does not call the
answer-generation LLM. Prefer --query-graphs-jsonl for deterministic evaluation;
the MetaQA template parser is a convenience for local smoke batches.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.aggregation.score_aggregation import MatchScoreShareBuilder
from src.common.types import QueryEdge
from src.crypto.fss_cli_backend import FssCliBackend
from src.crypto.hmac_ids import HmacIdProvider
from src.orchestration.cross_party_frontier_matcher import CrossPartyFrontierMatcher
from src.party.secure_index import SecurePartyIndex
from src.ranking.garbled_circuit import LocalGarbledCircuitTopK
from src.runtime.simgrag_loader import SimgragManifest, load_manifest, load_party_payload
from src.semantic.simgrag_embeddings import embedder_from_config

_BRACKET_RE = re.compile(r"\[([^\]]+)\]")


def _resolve(path: str | Path, base: Path = REPO_ROOT) -> Path:
    value = Path(path)
    return value if value.is_absolute() else (base / value).resolve()


def _load_base_config(manifest: SimgragManifest) -> dict:
    return json.loads(manifest.base_config.read_text())


def _load_metaqa_rows(manifest: SimgragManifest) -> list[dict]:
    config = _load_base_config(manifest)
    raw_data_dir = _resolve(config["raw_data_dir"], manifest.base_config.parent)
    hop = int(config["hop"])
    if hop == 1:
        qa_path = raw_data_dir / "1-hop" / "vanilla" / "qa_test.txt"
    else:
        qa_path = raw_data_dir / f"{hop}-hop" / f"{hop}-hop" / "vanilla" / "qa_test.txt"

    rows = []
    with qa_path.open("r", encoding="utf-8") as handle:
        for index, line in enumerate(handle):
            query, groundtruth = line.rstrip("\n").split("\t", 1)
            rows.append(
                {
                    "index": index,
                    "query": query.replace("[", "").replace("]", ""),
                    "raw_query": query,
                    "groundtruths": groundtruth.split("|"),
                    "query_graph": None,
                }
            )
    return rows


def _load_graph_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for index, line in enumerate(handle):
            if not line.strip():
                continue
            row = json.loads(line)
            if "query_graph" not in row:
                raise ValueError(f"Missing query_graph in {path}:{index + 1}")
            row.setdefault("index", index)
            row.setdefault("query", row.get("question"))
            row.setdefault("groundtruths", [])
            rows.append(row)
    return rows


def _contains_any(text: str, words: Iterable[str]) -> bool:
    return any(word in text for word in words)


def _answer_relation(question: str) -> str | None:
    text = question.casefold()
    if _contains_any(text, ("language", "languages", "spoken")):
        return "in_language"
    if _contains_any(text, ("genre", "genres", "types", "type")):
        return "has_genre"
    if _contains_any(text, ("release", "released", "when", "year", "years")):
        return "release_year"
    if _contains_any(text, ("directed by who", "directors", "director", "directed")):
        return "directed_by"
    if _contains_any(text, ("written by who", "writers", "writer", "screenwriters", "screenwriter", "wrote")):
        return "written_by"
    if _contains_any(text, ("starred", "actors", "actor", "person", "appeared")):
        return "starred_actors"
    return None


def _seed_relation(question: str) -> str | None:
    text = question.casefold()
    if _contains_any(text, ("share actors", "same actor", "starred by", "acted by", "actors in", "actor of")):
        return "starred_actors"
    if _contains_any(text, ("share directors", "co-directors", "directed by", "director of", "films directed", "movies directed")):
        return "directed_by"
    if _contains_any(text, ("share writers", "co-wrote", "written by", "writer of", "films written", "movies written")):
        return "written_by"
    return None


def _shared_relation(question: str) -> str | None:
    text = question.casefold()
    if _contains_any(text, ("share actors", "same actor", "also appear")):
        return "starred_actors"
    if _contains_any(text, ("share directors", "also directed", "co-directors")):
        return "directed_by"
    if _contains_any(text, ("share writers", "also wrote", "co-wrote")):
        return "written_by"
    return None


def _parse_metaqa_graph(question: str, hop: int) -> tuple[list[QueryEdge] | None, str]:
    match = _BRACKET_RE.search(question)
    if match is None:
        return None, "missing bracketed topic entity"

    topic = match.group(1).strip()
    shared = _shared_relation(question)
    seed = _seed_relation(question)
    answer = _answer_relation(question)
    relations: list[str] = []

    if shared is not None:
        relations.extend([shared, shared])
    elif seed is not None:
        relations.append(seed)

    if answer is not None and (not relations or relations[-1] != answer or hop > len(relations)):
        relations.append(answer)

    if not relations:
        return None, "could not infer relation sequence"
    relations = relations[:hop]
    if len(relations) < hop:
        return None, f"inferred {len(relations)} relation(s), expected {hop}"

    graph: list[QueryEdge] = []
    current = topic
    for edge_index, relation in enumerate(relations):
        target = "UNKNOWN answer 1" if edge_index == len(relations) - 1 else f"UNKNOWN entity {edge_index + 1}"
        graph.append((current, relation, target))
        current = target
    return graph, "parsed"


def _load_rows(args: argparse.Namespace, manifest: SimgragManifest) -> list[dict]:
    if args.query_graphs_jsonl:
        return _load_graph_jsonl(_resolve(args.query_graphs_jsonl))
    if manifest.dataset != "metaqa":
        raise ValueError("--query-graphs-jsonl is required for non-MetaQA datasets")

    config = _load_base_config(manifest)
    rows = _load_metaqa_rows(manifest)
    for row in rows:
        graph, status = _parse_metaqa_graph(row["raw_query"], int(config["hop"]))
        row["query_graph"] = graph
        row["query_graph_source"] = "metaqa_template"
        row["query_graph_status"] = status
    return rows


def _evidence_hit(evidence: list[dict], groundtruths: list[str]) -> bool:
    if not groundtruths:
        return False
    payload = json.dumps(evidence, ensure_ascii=False).casefold()
    return any(str(answer).casefold() in payload for answer in groundtruths)


def _build_matcher(args: argparse.Namespace, manifest: SimgragManifest) -> CrossPartyFrontierMatcher:
    executable = _resolve(args.fss_cli)
    if not executable.exists():
        raise SystemExit(f"FSS CLI not found: {executable}. Build it with: cmake --build build/fss_cli")

    ids = HmacIdProvider.from_env(args.key_env)
    parties = [
        SecurePartyIndex.from_plain_graph(spec.party_id, *load_party_payload(spec.data_path), ids)
        for spec in manifest.parties
    ]
    semantic_embedder = None
    if args.embedding_backend == "simgrag":
        embedding_config = args.embedding_config or manifest.parties[0].config_path
        semantic_embedder = embedder_from_config(
            embedding_config,
            model_path=args.embedding_model_path,
            device=args.embedding_device,
        )
    backend = FssCliBackend.from_executable(
        executable,
        timeout_seconds=args.timeout,
        max_eval_batch_size=args.eval_batch_size,
    )
    share_count = max(2, len(parties))
    return CrossPartyFrontierMatcher(
        parties=parties,
        ids=ids,
        backend=backend,
        share_builder=MatchScoreShareBuilder(share_count=share_count),
        enable_semantic_relations=args.semantic_relations,
        enable_semantic_entities=args.semantic_entities,
        semantic_bucket_mode=args.semantic_bucket_mode,
        semantic_relation_penalty=args.semantic_relation_penalty,
        semantic_lsh_relation_penalty=args.semantic_lsh_relation_penalty,
        semantic_entity_penalty=args.semantic_entity_penalty,
        semantic_lsh_entity_penalty=args.semantic_lsh_entity_penalty,
        semantic_embedder=semantic_embedder,
    )


def _serialize_result(row: dict, ranked, elapsed: float, args: argparse.Namespace, party_count: int) -> dict:
    evidence = [
        {"score": item.score, "edges": item.edges, "reuse_nodes": item.reuse_nodes}
        for item in ranked.evidence
    ]
    return {
        "index": row.get("index"),
        "query": row.get("query"),
        "groundtruths": row.get("groundtruths", []),
        "query_graph": row.get("query_graph"),
        "query_graph_source": row.get("query_graph_source", "jsonl"),
        "retrieval_time": elapsed,
        "party_count": party_count,
        "semantic_relations": args.semantic_relations,
        "semantic_entities": args.semantic_entities,
        "semantic_bucket_mode": args.semantic_bucket_mode if args.semantic_relations or args.semantic_entities else None,
        "embedding_backend": args.embedding_backend if args.semantic_relations or args.semantic_entities else None,
        "selected_candidate_ids": ranked.selected_ids,
        "aggregated_candidate_count": len(ranked.aggregated_shares),
        "evidences": evidence,
        "evidence_contains_groundtruth": _evidence_hit(evidence, row.get("groundtruths", [])),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Batch secure private frontier retrieval")
    parser.add_argument("--manifest", required=True, help="Path to SimGRAG federated manifest JSON")
    parser.add_argument("--query-graphs-jsonl", help="JSONL records containing query_graph and optional query/groundtruths")
    parser.add_argument("--output", default="results/private_frontier_batch.jsonl")
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--max-queries", type=int, default=5)
    parser.add_argument("--fss-cli", default="build/fss_cli/fedkg-fss-cli")
    parser.add_argument("--key-env", default="FEDKG_SETUP_KEY")
    parser.add_argument("--topk", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--eval-batch-size", type=int, default=256)
    parser.add_argument("--semantic-relations", action="store_true")
    parser.add_argument("--semantic-entities", action="store_true")
    parser.add_argument("--semantic-bucket-mode", choices=["alias", "lsh", "hybrid"], default="hybrid")
    parser.add_argument("--embedding-backend", choices=["hashing", "simgrag"], default="hashing")
    parser.add_argument("--embedding-config")
    parser.add_argument("--embedding-model-path")
    parser.add_argument("--embedding-device")
    parser.add_argument("--semantic-relation-penalty", type=float, default=0.25)
    parser.add_argument("--semantic-lsh-relation-penalty", type=float, default=0.5)
    parser.add_argument("--semantic-entity-penalty", type=float, default=0.2)
    parser.add_argument("--semantic-lsh-entity-penalty", type=float, default=0.45)
    args = parser.parse_args()

    manifest = load_manifest(args.manifest)
    rows = _load_rows(args, manifest)
    selected_rows = rows[args.start :]
    if args.max_queries is not None:
        selected_rows = selected_rows[: args.max_queries]

    output = _resolve(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    matcher = _build_matcher(args, manifest)
    ranker = LocalGarbledCircuitTopK(party_count=max(2, len(matcher.parties)))

    summary = {"total": 0, "ok": 0, "errors": 0, "hits": 0, "retrieval_time": 0.0}
    with output.open("w", encoding="utf-8") as handle:
        for row in selected_rows:
            summary["total"] += 1
            if not row.get("query_graph"):
                record = {
                    "index": row.get("index"),
                    "query": row.get("query"),
                    "groundtruths": row.get("groundtruths", []),
                    "query_graph": None,
                    "query_graph_source": row.get("query_graph_source"),
                    "error_message": row.get("query_graph_status", "missing query graph"),
                }
                summary["errors"] += 1
            else:
                start = time.time()
                try:
                    ranked = matcher.retrieve_ranked(row["query_graph"], ranker, k=args.topk)
                    elapsed = time.time() - start
                    record = _serialize_result(row, ranked, elapsed, args, len(matcher.parties))
                    summary["ok"] += 1
                    summary["hits"] += int(record["evidence_contains_groundtruth"])
                    summary["retrieval_time"] += elapsed
                except Exception as exc:
                    record = {
                        "index": row.get("index"),
                        "query": row.get("query"),
                        "groundtruths": row.get("groundtruths", []),
                        "query_graph": row.get("query_graph"),
                        "error_message": str(exc),
                    }
                    summary["errors"] += 1
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    avg_time = summary["retrieval_time"] / summary["ok"] if summary["ok"] else 0.0
    print(
        json.dumps(
            {
                "output": str(output),
                "total": summary["total"],
                "ok": summary["ok"],
                "errors": summary["errors"],
                "evidence_hits": summary["hits"],
                "average_retrieval_time": avg_time,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
