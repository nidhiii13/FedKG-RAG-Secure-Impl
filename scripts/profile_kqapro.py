#!/usr/bin/env python3
"""Profile KQA Pro against the implemented two-hop retrieval functionality.

The current MPC backend evaluates a single anchored relation chain::

    source --relation_1--> middle --relation_2--> answer

KQA Pro is richer than this functionality. In particular, even its simplest
two-hop entity questions normally include ``FilterConcept`` operations. This
script therefore reports two deliberately separate notions:

* ``syntactic_candidates``: programs with one Find, two dependent Relate
  operations, their generated concept filters, and a terminal What;
* ``snapshot_path_equivalent``: syntactic candidates for which removing both
  concept filters leaves exactly the same endpoint entity IDs in the frozen
  KQA Pro KB, and those endpoint names exactly match the published answer.

Only the second group is exported for the current backend. This is not a full
KQA Pro evaluation and it does not imply that concept filters remain redundant
after a graph update.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


HF_BASE = "https://huggingface.co/datasets/drt/kqa_pro/resolve/main"
PUBLISHED_FILES = {
    "kb.json": 79_341_787,
    "train.json": 88_119_411,
    "val.json": 11_047_970,
    "test.json": 3_257_326,
}
DEFAULT_DATA_DIR = Path("data/kqa_pro/raw")
DEFAULT_OUT_DIR = Path("data/kqa_pro/profile")
CHAIN_FUNCTIONS = (
    "Find",
    "Relate",
    "FilterConcept",
    "Relate",
    "FilterConcept",
    "What",
)
CHAIN_DEPENDENCIES = ((), (0,), (1,), (2,), (3,), (4,))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def download_dataset(data_dir: Path, force: bool = False) -> None:
    """Download the complete published mirror without silently accepting truncation."""
    data_dir.mkdir(parents=True, exist_ok=True)
    for filename, expected_size in PUBLISHED_FILES.items():
        destination = data_dir / filename
        if destination.exists() and destination.stat().st_size == expected_size and not force:
            print(f"using {destination} ({expected_size:,} bytes)")
            continue
        if destination.exists() and not force:
            raise ValueError(
                f"{destination} has {destination.stat().st_size:,} bytes; expected "
                f"{expected_size:,}. Remove it or pass --force-download."
            )
        temporary = destination.with_suffix(destination.suffix + ".part")
        if temporary.exists():
            temporary.unlink()
        url = f"{HF_BASE}/{filename}"
        print(f"downloading {url}")
        urllib.request.urlretrieve(url, temporary)  # noqa: S310
        actual_size = temporary.stat().st_size
        if actual_size != expected_size:
            raise ValueError(
                f"truncated {filename}: downloaded {actual_size:,}, expected {expected_size:,}"
            )
        temporary.replace(destination)


def load_json(path: Path, expected_type: type) -> Any:
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, expected_type):
        raise ValueError(f"{path} must contain a {expected_type.__name__}")
    return payload


def normalise_dependencies(step: dict[str, Any]) -> tuple[int, ...]:
    dependencies = step.get("dependencies")
    if not isinstance(dependencies, list) or not all(isinstance(x, int) for x in dependencies):
        return (-1,)
    return tuple(dependencies)


def chain_rejection(program: Any) -> str | None:
    if not isinstance(program, list):
        return "program_not_list"
    functions = tuple(step.get("function") for step in program if isinstance(step, dict))
    if len(functions) != len(program):
        return "program_step_not_object"
    if functions != CHAIN_FUNCTIONS:
        if functions.count("Relate") != 2:
            return f"relate_count:{functions.count('Relate')}"
        if functions.count("Find") != 1:
            return f"anchor_count:{functions.count('Find')}"
        if functions[-1:] != ("What",):
            return f"terminal:{functions[-1] if functions else 'empty'}"
        return "unsupported_operator_or_shape"
    dependencies = tuple(normalise_dependencies(step) for step in program)
    if dependencies != CHAIN_DEPENDENCIES:
        return "not_single_dependency_chain"
    expected_inputs = (1, 2, 1, 2, 1, 0)
    for step, count in zip(program, expected_inputs, strict=True):
        inputs = step.get("inputs")
        if not isinstance(inputs, list) or len(inputs) != count:
            return f"bad_inputs:{step.get('function')}"
    for index in (1, 3):
        if program[index]["inputs"][1] not in {"forward", "backward"}:
            return "bad_relation_direction"
    return None


@dataclass(frozen=True)
class Chain:
    source_name: str
    relation_1: str
    direction_1: str
    middle_concept: str
    relation_2: str
    direction_2: str
    answer_concept: str

    @classmethod
    def from_program(cls, program: list[dict[str, Any]]) -> "Chain":
        return cls(
            source_name=str(program[0]["inputs"][0]),
            relation_1=str(program[1]["inputs"][0]),
            direction_1=str(program[1]["inputs"][1]),
            middle_concept=str(program[2]["inputs"][0]),
            relation_2=str(program[3]["inputs"][0]),
            direction_2=str(program[3]["inputs"][1]),
            answer_concept=str(program[4]["inputs"][0]),
        )


class KQAIndex:
    """Minimal independent executor for Find/Relate/FilterConcept/What."""

    def __init__(self, kb: dict[str, Any]):
        concepts = kb.get("concepts")
        entities = kb.get("entities")
        if not isinstance(concepts, dict) or not isinstance(entities, dict):
            raise ValueError("kb.json must contain object-valued concepts and entities")
        self.concepts: dict[str, dict[str, Any]] = concepts
        self.entities: dict[str, dict[str, Any]] = entities
        self.entity_ids_by_name: dict[str, list[str]] = defaultdict(list)
        self.concept_ids_by_name: dict[str, list[str]] = defaultdict(list)
        self.adjacency: dict[tuple[str, str, str], set[str]] = defaultdict(set)
        self.relation_records = 0
        self.predicates: set[str] = set()
        self.traversal_labels: set[str] = set()

        for entity_id, entity in entities.items():
            self.entity_ids_by_name[str(entity.get("name", ""))].append(entity_id)
            relations = entity.get("relations", [])
            if not isinstance(relations, list):
                raise ValueError(f"entity {entity_id} relations must be a list")
            for relation in relations:
                if not isinstance(relation, dict):
                    continue
                predicate = relation.get("predicate")
                target = relation.get("object")
                direction = relation.get("direction")
                if not all(isinstance(x, str) for x in (predicate, target, direction)):
                    continue
                if direction not in {"forward", "backward"}:
                    continue
                self.adjacency[(entity_id, predicate, direction)].add(target)
                self.predicates.add(predicate)
                self.traversal_labels.add(traversal_label(predicate, direction))
                self.relation_records += 1
        for concept_id, concept in concepts.items():
            self.concept_ids_by_name[str(concept.get("name", ""))].append(concept_id)

        self._ancestor_cache: dict[str, frozenset[str]] = {}

    def ancestors(self, concept_id: str, visiting: frozenset[str] = frozenset()) -> frozenset[str]:
        cached = self._ancestor_cache.get(concept_id)
        if cached is not None:
            return cached
        if concept_id in visiting:
            return frozenset({concept_id})
        record = self.concepts.get(concept_id, {})
        parents = record.get("instanceOf", record.get("subclassOf", []))
        if not isinstance(parents, list):
            parents = []
        result = {concept_id}
        next_visiting = visiting | {concept_id}
        for parent in parents:
            if isinstance(parent, str):
                result.update(self.ancestors(parent, next_visiting))
        frozen = frozenset(result)
        self._ancestor_cache[concept_id] = frozen
        return frozen

    def matches_concept(self, entity_id: str, concept_name: str) -> bool:
        wanted = self.concept_ids_by_name.get(concept_name, [])
        if len(wanted) != 1:
            return False
        wanted_id = wanted[0]
        entity = self.entities.get(entity_id)
        if entity is None:
            return False
        direct = entity.get("instanceOf", [])
        return isinstance(direct, list) and any(
            isinstance(concept_id, str) and wanted_id in self.ancestors(concept_id)
            for concept_id in direct
        )

    def resolve_unique_entity(self, name: str) -> tuple[str | None, str | None]:
        matches = self.entity_ids_by_name.get(name, [])
        if not matches:
            return None, "source_not_found"
        if len(matches) != 1:
            return None, "source_name_ambiguous"
        return matches[0], None

    def relate(self, entity_ids: Iterable[str], predicate: str, direction: str) -> set[str]:
        result: set[str] = set()
        for entity_id in entity_ids:
            result.update(self.adjacency.get((entity_id, predicate, direction), ()))
        return result

    def names(self, entity_ids: Iterable[str]) -> set[str]:
        return {
            str(self.entities[entity_id].get("name", ""))
            for entity_id in entity_ids
            if entity_id in self.entities
        }


def traversal_label(predicate: str, direction: str) -> str:
    return predicate if direction == "forward" else f"{predicate}_inverse"


def inspect_candidate(index: KQAIndex, chain: Chain, published_answer: Any) -> dict[str, Any]:
    source_id, source_error = index.resolve_unique_entity(chain.source_name)
    if source_error:
        return {"path_equivalent": False, "reason": source_error}
    assert source_id is not None

    first_all = index.relate({source_id}, chain.relation_1, chain.direction_1)
    first_filtered = {
        entity_id for entity_id in first_all if index.matches_concept(entity_id, chain.middle_concept)
    }
    second_all = index.relate(first_all, chain.relation_2, chain.direction_2)
    second_from_filtered_middle = index.relate(
        first_filtered, chain.relation_2, chain.direction_2
    )
    second_filtered = {
        entity_id
        for entity_id in second_from_filtered_middle
        if index.matches_concept(entity_id, chain.answer_concept)
    }

    filtered_names = index.names(second_filtered)
    answer_text = published_answer if isinstance(published_answer, str) else ""
    published_matches_executor = filtered_names == {answer_text}
    # Requiring equality at both stages is stronger than merely comparing final
    # endpoints. An extra middle entity that happens to have no r2 edge would
    # not alter an unbounded answer, but it could consume a bounded MPC frontier
    # slot and therefore is not safe to call compatible with this backend.
    path_equivalent = (
        first_all == first_filtered
        and second_from_filtered_middle == second_filtered
        and second_all == second_filtered
        and published_matches_executor
    )
    if not first_all:
        reason = "empty_first_hop"
    elif not first_filtered:
        reason = "empty_filtered_first_hop"
    elif not second_all:
        reason = "empty_second_hop"
    elif not published_matches_executor:
        reason = "independent_executor_answer_mismatch"
    elif first_all != first_filtered:
        reason = "middle_concept_filter_changes_frontier"
    elif second_from_filtered_middle != second_filtered:
        reason = "answer_concept_filter_changes_result"
    elif second_all != second_filtered:
        reason = "concept_filters_change_result"
    else:
        reason = "snapshot_path_equivalent"

    return {
        "path_equivalent": path_equivalent,
        "reason": reason,
        "source_id": source_id,
        "first_hop_unfiltered": len(first_all),
        "first_hop_filtered": len(first_filtered),
        "second_hop_unfiltered": len(second_all),
        "second_hop_filtered": len(second_filtered),
        "endpoint_ids": sorted(second_filtered),
        "endpoint_names": sorted(filtered_names),
        "published_answer_matches_executor": published_matches_executor,
    }


def profile(
    kb: dict[str, Any],
    split_rows: dict[str, list[dict[str, Any]]],
    out_dir: Path,
    limit: int | None = None,
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    index = KQAIndex(kb)
    rejection_reasons: Counter[str] = Counter()
    candidate_outcomes: Counter[str] = Counter()
    split_totals: Counter[str] = Counter()
    split_candidates: Counter[str] = Counter()
    split_compatible: Counter[str] = Counter()
    compatible_relations: set[str] = set()
    compatible_relation_pairs: set[tuple[str, str]] = set()
    candidates_path = out_dir / "kqapro_twohop_syntactic_candidates.jsonl"
    compatible_path = out_dir / "kqapro_twohop_path_equivalent.jsonl"

    with candidates_path.open("w", encoding="utf-8") as candidate_handle, compatible_path.open(
        "w", encoding="utf-8"
    ) as compatible_handle:
        for split, rows in split_rows.items():
            selected = rows if limit is None else rows[:limit]
            for row_index, row in enumerate(selected):
                split_totals[split] += 1
                program = row.get("program")
                rejection = chain_rejection(program)
                if rejection:
                    rejection_reasons[rejection] += 1
                    continue
                split_candidates[split] += 1
                chain = Chain.from_program(program)
                inspection = inspect_candidate(index, chain, row.get("answer"))
                candidate_outcomes[inspection["reason"]] += 1
                uid = f"{split}:{row_index}"
                relation_1 = traversal_label(chain.relation_1, chain.direction_1)
                relation_2 = traversal_label(chain.relation_2, chain.direction_2)
                record = {
                    "uid": uid,
                    "split": split,
                    "question": row.get("question"),
                    "answer": row.get("answer"),
                    "choices": row.get("choices"),
                    "source": chain.source_name,
                    "relation_1": relation_1,
                    "relation_1_predicate": chain.relation_1,
                    "relation_1_direction": chain.direction_1,
                    "middle_concept": chain.middle_concept,
                    "relation_2": relation_2,
                    "relation_2_predicate": chain.relation_2,
                    "relation_2_direction": chain.direction_2,
                    "answer_concept": chain.answer_concept,
                    "program": program,
                    "sparql": row.get("sparql"),
                    **inspection,
                }
                candidate_handle.write(json.dumps(record, ensure_ascii=False) + "\n")
                if not inspection["path_equivalent"]:
                    continue
                split_compatible[split] += 1
                compatible_relations.update((relation_1, relation_2))
                compatible_relation_pairs.add((relation_1, relation_2))
                export = {
                    **record,
                    "groundtruths": inspection["endpoint_names"],
                    "query_graph": [
                        [chain.source_name, relation_1, "UNKNOWN"],
                        ["UNKNOWN", relation_2, "ANSWER"],
                    ],
                    "compatibility_scope": "frozen_kb_snapshot_path_equivalent",
                }
                compatible_handle.write(json.dumps(export, ensure_ascii=False) + "\n")

    total_rows = sum(split_totals.values())
    total_candidates = sum(split_candidates.values())
    total_compatible = sum(split_compatible.values())
    entity_count = len(index.entities)
    traversal_relation_count = len(index.traversal_labels)
    summary = {
        "dataset": "KQA Pro",
        "scope": "strict anchored two-Relate entity paths under the frozen KB snapshot",
        "not_full_dataset_accuracy": True,
        "program_shape": list(CHAIN_FUNCTIONS),
        "total_rows_profiled": total_rows,
        "syntactic_candidates": total_candidates,
        "syntactic_candidate_rate": total_candidates / total_rows if total_rows else 0.0,
        "snapshot_path_equivalent": total_compatible,
        "snapshot_path_equivalent_rate": total_compatible / total_rows if total_rows else 0.0,
        "candidate_acceptance_rate": total_compatible / total_candidates if total_candidates else 0.0,
        "by_split": {
            split: {
                "rows": split_totals[split],
                "syntactic_candidates": split_candidates[split],
                "snapshot_path_equivalent": split_compatible[split],
            }
            for split in split_rows
        },
        "rejection_reasons": dict(rejection_reasons.most_common()),
        "candidate_outcomes": dict(candidate_outcomes.most_common()),
        "kb": {
            "entities": entity_count,
            "concepts": len(index.concepts),
            "relation_records": index.relation_records,
            "relation_predicates": len(index.predicates),
            "directed_traversal_labels": traversal_relation_count,
            "dense_entity_relation_rows": entity_count * traversal_relation_count,
        },
        "compatible_subset": {
            "directed_relations": len(compatible_relations),
            "directed_relation_pairs": len(compatible_relation_pairs),
        },
        "outputs": {
            "syntactic_candidates": str(candidates_path),
            "path_equivalent": str(compatible_path),
        },
        "limitations": [
            "KQA Pro concept filters are not implemented by the current MPC backend.",
            "Accepted rows are only those for which both filters are result-redundant on this frozen KB.",
            "Path equivalence may cease to hold after graph updates.",
            "The hidden KQA Pro test split has no programs or answers and cannot be compatibility-profiled.",
            "KQA Pro has no natural owner provenance; any federation split is synthetic.",
        ],
    }
    summary_path = out_dir / "kqapro_compatibility_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return summary


def write_provenance(data_dir: Path, out_dir: Path) -> None:
    records = {}
    for filename, expected_size in PUBLISHED_FILES.items():
        path = data_dir / filename
        if not path.exists():
            continue
        records[filename] = {
            "bytes": path.stat().st_size,
            "expected_bytes": expected_size,
            "sha256": sha256_file(path),
            "source": f"{HF_BASE}/{filename}",
        }
    provenance = {
        "dataset": "KQA Pro",
        "canonical_repository": "https://github.com/shijx12/KQAPro_Baselines",
        "paper": "https://doi.org/10.18653/v1/2022.acl-long.422",
        "download_note": (
            "The canonical Tsinghua share was unavailable when this pipeline was run; "
            "files came from the drt/kqa_pro Hugging Face mirror."
        ),
        "files": records,
    }
    (out_dir / "PROVENANCE.json").write_text(
        json.dumps(provenance, indent=2) + "\n", encoding="utf-8"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--force-download", action="store_true")
    parser.add_argument(
        "--splits", nargs="+", choices=("train", "val"), default=("train", "val")
    )
    parser.add_argument("--limit", type=int, help="profile at most this many rows per split")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.download or args.force_download:
        download_dataset(args.data_dir, force=args.force_download)
    required = [args.data_dir / "kb.json", *(args.data_dir / f"{s}.json" for s in args.splits)]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        print("missing KQA Pro files: " + ", ".join(missing), file=sys.stderr)
        print("run again with --download", file=sys.stderr)
        return 2
    kb = load_json(args.data_dir / "kb.json", dict)
    rows = {split: load_json(args.data_dir / f"{split}.json", list) for split in args.splits}
    summary = profile(kb, rows, args.out, args.limit)
    write_provenance(args.data_dir, args.out)
    print(
        f"profiled {summary['total_rows_profiled']:,} rows: "
        f"{summary['syntactic_candidates']:,} syntactic two-hop candidates, "
        f"{summary['snapshot_path_equivalent']:,} snapshot-path-equivalent"
    )
    print(f"wrote {args.out / 'kqapro_compatibility_summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
