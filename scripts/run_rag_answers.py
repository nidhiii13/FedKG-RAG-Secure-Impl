#!/usr/bin/env python3
"""Answer from an existing run_rag_eval retrieval log without rerunning retrieval."""

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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--llm-config", type=Path, required=True)
    parser.add_argument("--answers", type=int, default=50)
    parser.add_argument("--seed", type=int, default=4242)
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--max-tokens", type=int, default=40)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()

    per_question = args.run_dir / "per_question.jsonl"
    if not per_question.exists():
        raise SystemExit(f"missing retrieval log: {per_question}")

    rows = [
        json.loads(line)
        for line in per_question.read_text(encoding="utf-8").splitlines()
        if '"hit"' in line
    ]
    if not rows:
        raise SystemExit(f"no answerable retrieval rows in {per_question}")

    picked = random.Random(args.seed).sample(rows, min(args.answers, len(rows)))
    out_path = args.out or (args.run_dir / "answers_retry.jsonl")

    from openai import OpenAI

    conf = json.loads(args.llm_config.read_text(encoding="utf-8"))
    llm = conf.get("llm", conf)
    client = OpenAI(
        base_url=llm["base_url"],
        api_key=llm.get("api_key", "ollama"),
        max_retries=0,
    )

    correct = answered = 0
    errors: Counter[str] = Counter()
    started = time.time()
    with out_path.open("w", encoding="utf-8") as log:
        for position, row in enumerate(picked, start=1):
            facts = "\n".join(
                " ; ".join(f"{h} -{r}-> {t}" for h, r, t in item["edges"])
                for item in row["evidence"]
            )
            prompt = (
                "Answer using ONLY these retrieved facts.\n\n"
                f"Facts:\n{facts}\n\n"
                f"Question: {row['query']}\n"
                "Answer with names only, comma separated."
            )
            try:
                answer = client.chat.completions.create(
                    model=llm["model"],
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.0,
                    max_tokens=args.max_tokens,
                    timeout=args.timeout,
                ).choices[0].message.content.strip()
            except Exception as exc:  # noqa: BLE001
                errors[type(exc).__name__] += 1
                log.write(json.dumps({"query": row["query"],
                                      "error": type(exc).__name__}) + "\n")
            else:
                ok = any(
                    str(groundtruth).casefold() in answer.casefold()
                    for groundtruth in row["groundtruths"]
                )
                correct += ok
                answered += 1
                log.write(json.dumps({
                    "query": row["query"],
                    "groundtruths": row["groundtruths"],
                    "answer": answer,
                    "correct": ok,
                }, ensure_ascii=False) + "\n")
            if position % 10 == 0:
                print(f"  answered {position}/{len(picked)}  "
                      f"successful {answered}, errors {sum(errors.values())}")

    low, high = wilson(correct, answered) if answered else (0.0, 0.0)
    summary = {
        "source_run_dir": str(args.run_dir),
        "answers_attempted": len(picked),
        "answers_scored": answered,
        "answers_correct": correct,
        "answer_accuracy": round(correct / answered, 4) if answered else None,
        "answer_accuracy_ci95": [round(low, 4), round(high, 4)] if answered else None,
        "answers_errors": sum(errors.values()),
        "answer_error_types": dict(errors.most_common()),
        "answer_seconds": round(time.time() - started, 1),
        "llm_model": llm["model"],
        "llm_timeout": args.timeout,
        "llm_max_tokens": args.max_tokens,
        "output": str(out_path),
    }
    summary_path = out_path.with_suffix(".summary.json")
    summary_path.write_text(json.dumps(summary, indent=1) + "\n", encoding="utf-8")
    print(f"answers: {correct}/{answered} correct, errors {dict(errors.most_common())}")
    print(f"wrote {out_path}")
    print(f"wrote {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
