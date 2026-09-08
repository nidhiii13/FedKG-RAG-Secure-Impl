#!/usr/bin/env python3
"""Ollama answer generation over CWQ retrieval output, evidence-only.

Reads a completed ``run_cwq_eval.py`` per_question.jsonl, samples N distinct
questions deterministically, and asks the LLM to answer **using only the
retrieved evidence**.  Retrieval misses are included, not silently dropped:
the summary separates overall accuracy from generation accuracy conditional on
retrieval having found a gold answer, so retrieval loss and generation loss
stay decomposed.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.run_rag_eval import wilson  # noqa: E402

DEFAULT_LLM_CONFIG = Path(
    ROOT.parent / "SimGRAG/configs/federated/webqsp_party_0.json"
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True,
                        help="directory holding per_question.jsonl")
    parser.add_argument("--answers", type=int, default=300)
    parser.add_argument("--seed", type=int, default=4242)
    parser.add_argument("--llm-config", type=Path, default=DEFAULT_LLM_CONFIG)
    parser.add_argument("--llm-timeout", type=float, default=120.0)
    parser.add_argument("--llm-max-tokens", type=int, default=80)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()

    from openai import OpenAI

    conf = json.loads(args.llm_config.read_text(encoding="utf-8"))
    llm = conf.get("llm", conf)
    client = OpenAI(base_url=llm["base_url"], api_key=llm.get("api_key", "ollama"),
                    max_retries=0)

    rows = [json.loads(line)
            for line in (args.run / "per_question.jsonl").read_text().splitlines()
            if line.strip()]
    ids = [row["id"] for row in rows]
    if len(ids) != len(set(ids)):
        raise SystemExit("per_question.jsonl contains duplicate ids")
    picked = sorted(rows, key=lambda r: r["id"])
    if args.answers and args.answers < len(picked):
        picked = random.Random(args.seed).sample(picked, args.answers)

    out_path = args.run / "answers_a300.jsonl"
    done: dict[str, dict] = {}
    if args.resume and out_path.exists():
        for line in out_path.read_text().splitlines():
            try:
                row = json.loads(line)
                done[row["id"]] = row
            except (json.JSONDecodeError, KeyError):
                continue
        print(f"resume: {len(done)} answers already recorded")

    started = time.time()
    errors: Counter[str] = Counter()
    mode = "a" if done else "w"
    with out_path.open(mode, encoding="utf-8") as log:
        for position, row in enumerate(
            [r for r in picked if r["id"] not in done], start=1
        ):
            facts = "\n".join(
                " ; ".join(f"{h} -{r}-> {t}" for h, r, t in item["edges"])
                for item in row["evidence"]
            ) or "(no facts retrieved)"
            prompt = (f"Answer using ONLY these retrieved facts.\n\nFacts:\n{facts}"
                      f"\n\nQuestion: {row['query']}\n"
                      "Answer with names only, comma separated.")
            record = {"id": row["id"], "query": row["query"],
                      "groundtruths": row["groundtruths"],
                      "retrieval_hit": bool(row["hit"])}
            try:
                answer = client.chat.completions.create(
                    model=llm["model"],
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.0,
                    max_tokens=args.llm_max_tokens,
                    timeout=args.llm_timeout,
                ).choices[0].message.content.strip()
                record["answer"] = answer
                record["correct"] = any(
                    str(g).casefold() in answer.casefold()
                    for g in row["groundtruths"]
                )
            except Exception as exc:  # noqa: BLE001
                errors[type(exc).__name__] += 1
                record["error"] = type(exc).__name__
            log.write(json.dumps(record, ensure_ascii=False) + "\n")
            log.flush()
            if position % 10 == 0:
                print(f"  {position} answered, {sum(errors.values())} errors, "
                      f"{time.time() - started:.0f}s elapsed")

    results = [json.loads(line) for line in out_path.read_text().splitlines()]
    scored = [r for r in results if "correct" in r]
    correct = sum(r["correct"] for r in scored)
    hit_rows = [r for r in scored if r["retrieval_hit"]]
    hit_correct = sum(r["correct"] for r in hit_rows)
    low, high = wilson(correct, len(scored))
    summary = {
        "run": str(args.run),
        "llm_model": llm["model"],
        "llm_timeout": args.llm_timeout,
        "llm_max_tokens": args.llm_max_tokens,
        "questions_sampled": len(picked),
        "unique_ids": len({r["id"] for r in picked}),
        "answers_scored": len(scored),
        "answer_errors": sum(1 for r in results if "error" in r),
        "answer_error_types": dict(errors.most_common()),
        "overall_correct": correct,
        "overall_accuracy": correct / len(scored) if scored else None,
        "overall_accuracy_ci95": [low, high],
        "retrieval_hits_in_sample": len(hit_rows),
        "generation_correct_given_retrieval_hit": hit_correct,
        "generation_accuracy_given_retrieval_hit":
            hit_correct / len(hit_rows) if hit_rows else None,
        "retrieval_misses_included_not_dropped": True,
        "answer_seconds": time.time() - started,
    }
    (args.run / "answers_a300.summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
