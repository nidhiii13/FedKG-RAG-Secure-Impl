#!/usr/bin/env python3
"""SimGRAG-style private E2E runner: rewrite, secure retrieve, answer.

This script is intended for local fair comparison experiments. The online secure
retrieval path does not query a central Milvus instance with plaintext query
embeddings. Semantic matching is performed through party-local/private semantic
bucket indexes, while Ollama is used only for the same rewrite and answer stages
used by the baseline SimGRAG batch flow.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = Path(__file__).resolve().parent
SIMGRAG_DEFAULT_ROOT = REPO_ROOT.parent / "SimGRAG"
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(SCRIPT_DIR))

from run_private_frontier_batch import (  # noqa: E402
    _build_matcher,
    _evidence_hit,
    _load_rows,
    _resolve,
)
from src.ranking.garbled_circuit import LocalGarbledCircuitTopK  # noqa: E402
from src.runtime.simgrag_loader import load_manifest  # noqa: E402


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot import {name} from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_openai_client(config: dict):
    try:
        from openai import OpenAI
    except ImportError as exc:
        raise SystemExit("Missing dependency 'openai'. Install with: .venv/bin/pip install -r requirements.txt") from exc

    llm_config = config["llm"]
    return OpenAI(base_url=llm_config["base_url"], api_key=llm_config["api_key"])


def _chat(client, config: dict, prompt: str) -> str:
    llm_config = config["llm"]
    completion = client.chat.completions.create(
        model=llm_config["model"],
        messages=[{"role": "user", "content": prompt}],
        temperature=llm_config.get("temperature", 0.2),
        top_p=llm_config.get("top_p", 0.1),
        max_tokens=llm_config.get("max_tokens", 1024),
    )
    return completion.choices[0].message.content.strip()


def _extract_graph(llm_output: str) -> list[list[str]]:
    try:
        matched = re.search(r"\{.*?\}", llm_output, re.DOTALL)
        if matched is None:
            raise ValueError("no JSON-like object found")
        decoded = eval(matched.group(0), {"__builtins__": {}}, {})
        return [list(edge) for edge in decoded["graph"]]
    except Exception as exc:
        # MetaQA prompts request Python-like tuples. Names such as Pat O'Brien
        # make that representation invalid when the model uses single quotes,
        # so recover only the three explicitly delimited tuple fields.
        graph_match = re.search(
            r"[\"']graph[\"']\s*:\s*\[(.*)\]\s*\}",
            llm_output,
            re.DOTALL,
        )
        if graph_match is not None:
            graph_body = graph_match.group(1)
            edges = re.findall(
                r"\(\s*'(.*?)'\s*,\s*'(.*?)'\s*,\s*'(.*?)'\s*\)",
                graph_body,
                re.DOTALL,
            )
            if not edges:
                edges = re.findall(
                    r'\(\s*"(.*?)"\s*,\s*"(.*?)"\s*,\s*"(.*?)"\s*\)',
                    graph_body,
                    re.DOTALL,
                )
            if edges:
                return [list(edge) for edge in edges]
        raise ValueError("Failed to decode rewritten graph") from exc


def _load_config(path: Path, device: str | None = None) -> dict:
    config = json.loads(path.read_text())
    if device:
        config.setdefault("embedding_model", {})["device"] = device
    return config


def _load_prompt_modules(simgrag_root: Path, dataset: str) -> tuple[Any, Any]:
    if dataset != "metaqa":
        raise ValueError("This E2E runner currently supports MetaQA prompts only")
    rewrite = _load_module(simgrag_root / "prompts" / "rewrite_metaQA.py", "simgrag_rewrite_metaqa")
    answer = _load_module(simgrag_root / "prompts" / "answer_metaQA.py", "simgrag_answer_metaqa")
    return rewrite, answer


def _plain_evidences(ranked) -> list[list[tuple[str, str, str]]]:
    return [item.edges for item in ranked.evidence]


def _serialize_evidence(ranked) -> list[dict]:
    return [
        {"score": item.score, "edges": item.edges, "reuse_nodes": item.reuse_nodes}
        for item in ranked.evidence
    ]


def _progress_line(position: int, total: int, record: dict) -> str:
    status = "ERR" if record.get("error_message") else "OK"
    hit = "hit" if record.get("evidence_contains_groundtruth") else "miss"
    correct = record.get("correct")
    answer = ""
    if correct is not None:
        answer = f" answer={'correct' if correct else 'wrong'}"
    retrieval_time = record.get("retrieval_time", 0.0)
    answer_time = record.get("answer_time", 0.0)
    candidates = record.get("aggregated_candidate_count", 0)
    query = str(record.get("query") or "").replace("\n", " ")[:90]
    return (
        f"[{position}/{total}] {status} index={record.get('index')} "
        f"{hit}{answer} candidates={candidates} "
        f"retrieval={retrieval_time:.2f}s answer={answer_time:.2f}s "
        f"query={query}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SimGRAG-style private E2E secure frontier queries")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--query-graphs-jsonl", help="Optional saved query_graph records for fair retrieval comparison")
    parser.add_argument("--output", default="results/private_frontier_e2e.jsonl")
    parser.add_argument("--append", action="store_true", help="Append JSONL records to --output instead of overwriting it")
    parser.add_argument("--simgrag-root", default=str(SIMGRAG_DEFAULT_ROOT))
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--max-queries", type=int, default=5)
    parser.add_argument("--rewrite-with-ollama", action="store_true", help="Rewrite rows without query_graph using Ollama")
    parser.add_argument(
        "--force-rewrite",
        action="store_true",
        help="Ignore any loaded/template query_graph and rewrite each query with Ollama",
    )
    parser.add_argument("--answer-with-ollama", action="store_true", help="Generate final answers from secure evidence using Ollama")
    parser.add_argument("--quiet", action="store_true", help="Disable per-query progress lines")
    parser.add_argument("--device", help="Override device in the SimGRAG LLM/embedding config where applicable")
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
    simgrag_root = _resolve(args.simgrag_root)
    first_config = _load_config(manifest.parties[0].config_path, device=args.device)
    rewrite_prompt, answer_prompt = _load_prompt_modules(simgrag_root, manifest.dataset)
    llm_client = None
    if args.rewrite_with_ollama or args.answer_with_ollama:
        llm_client = _load_openai_client(first_config)

    rows = _load_rows(args, manifest)
    selected_rows = rows[args.start :]
    if args.max_queries is not None:
        selected_rows = selected_rows[: args.max_queries]

    matcher = _build_matcher(args, manifest)
    ranker = LocalGarbledCircuitTopK(party_count=max(2, len(matcher.parties)))
    output = _resolve(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    summary = {
        "total": 0,
        "ok": 0,
        "errors": 0,
        "evidence_hits": 0,
        "answer_correct": 0,
        "rewrite_time": 0.0,
        "retrieval_time": 0.0,
        "answer_time": 0.0,
    }

    total_rows = len(selected_rows)
    output_mode = "a" if args.append else "w"
    with output.open(output_mode, encoding="utf-8") as handle:
        for position, row in enumerate(selected_rows, start=1):
            summary["total"] += 1
            record = {
                "index": row.get("index"),
                "query": row.get("query"),
                "groundtruths": row.get("groundtruths", []),
                "query_graph": row.get("query_graph"),
                "query_graph_source": row.get("query_graph_source", "jsonl" if args.query_graphs_jsonl else "loader"),
                "federated_correct": row.get("federated_correct"),
                "federated_retrieval_time": row.get("federated_retrieval_time"),
            }
            try:
                if args.force_rewrite:
                    record["original_query_graph"] = record["query_graph"]
                    record["query_graph"] = None
                    record["query_graph_source"] = "ollama_rewrite"
                if not record["query_graph"]:
                    if not args.rewrite_with_ollama:
                        raise ValueError("missing query_graph; pass --rewrite-with-ollama or --query-graphs-jsonl")
                    rewrite_start = time.time()
                    record["rewrite_prompt"] = rewrite_prompt.get(
                        record["query"],
                        shot=first_config.get("rewrite_shot", 12),
                    )
                    record["rewrite_llm_output"] = _chat(llm_client, first_config, record["rewrite_prompt"])
                    record["rewrite_time"] = time.time() - rewrite_start
                    record["query_graph"] = _extract_graph(record["rewrite_llm_output"])
                    record["query_graph_source"] = "ollama_rewrite"
                    summary["rewrite_time"] += record["rewrite_time"]

                retrieval_start = time.time()
                ranked = matcher.retrieve_ranked(record["query_graph"], ranker, k=args.topk)
                record["retrieval_time"] = time.time() - retrieval_start
                record["selected_candidate_ids"] = ranked.selected_ids
                record["aggregated_candidate_count"] = len(ranked.aggregated_shares)
                record["evidences"] = _serialize_evidence(ranked)
                record["evidence_contains_groundtruth"] = _evidence_hit(
                    record["evidences"],
                    record["groundtruths"],
                )
                summary["retrieval_time"] += record["retrieval_time"]
                summary["evidence_hits"] += int(record["evidence_contains_groundtruth"])

                if args.answer_with_ollama:
                    answer_start = time.time()
                    record["answer_prompt"] = answer_prompt.get(
                        record["query"],
                        _plain_evidences(ranked),
                        shot=first_config.get("answer_shot", 12),
                    )
                    record["answer_llm_output"] = _chat(llm_client, first_config, record["answer_prompt"])
                    record["answer_time"] = time.time() - answer_start
                    record["correct"] = any(
                        str(gt).casefold() in record["answer_llm_output"].casefold()
                        for gt in record["groundtruths"]
                    )
                    summary["answer_time"] += record["answer_time"]
                    summary["answer_correct"] += int(record["correct"])

                summary["ok"] += 1
            except Exception as exc:
                record["error_message"] = str(exc)
                summary["errors"] += 1

            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            handle.flush()
            if not args.quiet:
                print(_progress_line(position, total_rows, record), flush=True)

    ok = summary["ok"] or 1
    print(
        json.dumps(
            {
                "output": str(output),
                "total": summary["total"],
                "ok": summary["ok"],
                "errors": summary["errors"],
                "evidence_hits": summary["evidence_hits"],
                "answer_correct": summary["answer_correct"] if args.answer_with_ollama else None,
                "average_rewrite_time": summary["rewrite_time"] / ok,
                "average_retrieval_time": summary["retrieval_time"] / ok,
                "average_answer_time": summary["answer_time"] / ok,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
