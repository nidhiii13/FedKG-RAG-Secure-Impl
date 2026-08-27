#!/usr/bin/env python3
"""End-to-end multi-party FSS evaluation over the repository's real datasets.

For each dataset, this harness:
  1. builds the federated party KGs (real party pickles for MetaQA and the
     5-party WebQSP federation; the user-built 3-owner fixtures for KQA Pro
     and CWQ-closure; RoG per-question subgraph unions for CWQ-RoG; a
     term-universe fixture for LC-QuAD 2.0),
  2. encodes them into plaintext-free opaque snapshots (HMAC IDs) and
     replicates them to N evaluator stores (multiparty_fss.replication),
  3. runs each query's private lookups through the full N-party pipeline:
     rank encoding -> Gen^{p0} keygen -> one request per evaluator ->
     Eval^{p0} over the shared universe (dense mode) -> fail-closed
     coordinator XOR combine -> nonzero rank -> opaque candidate,
  4. derives answers where the dataset supports it, entirely in the encoded
     space (1-hop / 2-hop readout from the opaque snapshot adjacency after
     the private anchor lookups), and compares against HMAC-encoded gold,
  5. records per-stage timings (median of --repeats repetitions after a
     warm-up), sizes, hit/answer correctness, and negative controls (absent
     terms must reconstruct all-zero).

Two transports:
  --transport inprocess  (default) evaluators are in-process objects; no
                         marshaling; evaluator latency = max over N
                         (parallel model).
  --transport socket     N genuinely separated evaluator server processes
                         (tools/serve_multiparty_evaluator.py) on localhost
                         TCP; requests/responses fully JSON-marshaled; the N
                         round trips are issued from parallel threads and the
                         measured evaluator stage is the wall time of that
                         parallel section (marshaling + IPC included).

Privacy note: this measures functionality and cost. Timing/DB-content
visibility to evaluators is per the documented leakage model; nothing here is
a privacy proof.

Usage:
  .venv/bin/python multiparty_fss/benchmarks/eval_datasets.py \
      --dataset all --queries 50 --party-count 3 --repeats 3 --out /tmp/eval
  (add --scaling for MetaQA N=5,7; --transport socket for deployed mode)
"""

from __future__ import annotations

import argparse
import json
import platform
import re
import statistics
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import numpy as np

from src.crypto.hmac_ids import HmacIdProvider
from src.party.opaque_index_snapshot import OpaqueIndexSnapshot
from src.party.secure_index import SecurePartyIndex

from multiparty_fss.domain import UniverseDomain
from multiparty_fss.keygen import generate
from multiparty_fss.params import honest_majority_threshold
from multiparty_fss.replication import replicate_opaque_snapshots_multiparty
from multiparty_fss.requests import (
    MpFssCoordinator,
    MpFssEvaluatorRequest,
    MpFssEvaluatorResponse,
)
from multiparty_fss.service import (
    MultipartyFssEvaluatorService,
    MultipartyFssEvaluatorStore,
)
from multiparty_fss.transport import SocketEvaluatorClient

SIMGRAG = ROOT.parent / "SimGRAG"
EVAL_KEY = b"fedkg-mpfss-dataset-eval-key-2026"  # evaluation-only HMAC key
NEGATIVE_CONTROLS = 5

WD_ENTITY_RE = re.compile(r"wd:(Q\d+)")
WD_RELATION_RE = re.compile(r"wdt:(P\d+)")
WD_PAIR_RE = re.compile(r"(?:wd:(Q\d+)\s+wdt:(P\d+))|(?:wdt:(P\d+)\s+wd:(Q\d+))")


@dataclass
class TermLookup:
    label: str
    domain: str  # "entity" | "relation"
    expect_present: bool


@dataclass
class EvalQuery:
    qid: str
    question: str
    terms: list[TermLookup]
    kind: str  # "metaqa1hop" | "chain2" | "retrieval"
    topic: str | None = None
    relation: tuple[str, str] | None = None  # (label, "out"|"in")
    chain: tuple[str, str, str] | None = None  # (source, rel1, rel2)
    gold_answers: list[str] | None = None  # plaintext labels / entity IDs


@dataclass
class Workload:
    name: str
    partitions: dict[str, dict]  # party_id -> plain graph {h: {r: [t]}}
    queries: list[EvalQuery]
    notes: str = ""
    types: dict[str, dict] = field(default_factory=dict)  # party_id -> type map


# --------------------------------------------------------------------------
# Dataset loaders
# --------------------------------------------------------------------------


def _load_party_pickles(paths: dict[str, Path]) -> dict[str, dict]:
    import pickle

    partitions = {}
    for party_id, path in paths.items():
        with path.open("rb") as handle:
            payload = pickle.load(handle)
        partitions[party_id] = payload["graph"]
    return partitions


def load_metaqa(count: int) -> Workload:
    partitions = _load_party_pickles(
        {
            f"party_{pid}": SIMGRAG / f"data/metaQA/federated/party_{pid}/party.pkl"
            for pid in (0, 1)
        }
    )
    union: dict[str, dict[str, set]] = {}
    for graph in partitions.values():
        for head, rels in graph.items():
            for rel, targets in rels.items():
                union.setdefault(head, {}).setdefault(rel, set()).update(targets)
    reverse: dict[str, dict[str, set]] = {}
    for head, rels in union.items():
        for rel, targets in rels.items():
            for target in targets:
                reverse.setdefault(target, {}).setdefault(rel, set()).add(head)

    qa_path = SIMGRAG / "data/raw/metaQA/1-hop/vanilla/qa_test.txt"
    queries: list[EvalQuery] = []
    skipped = 0
    for line_no, line in enumerate(qa_path.read_text().splitlines()):
        if len(queries) >= count:
            break
        if "\t" not in line:
            continue
        question, answer_field = line.split("\t", 1)
        match = re.search(r"\[(.+?)\]", question)
        if not match:
            continue
        topic = match.group(1)
        gold = sorted({a.strip() for a in answer_field.split("|") if a.strip()})
        if topic not in union and topic not in reverse:
            skipped += 1
            continue
        found = None
        for rel_dir, index in (("out", union), ("in", reverse)):
            for rel in sorted(index.get(topic, {})):
                neighbors = {str(t) for t in index[topic][rel]}
                if neighbors == set(gold):
                    found = (rel, rel_dir)
                    break
            if found:
                break
        if found is None:
            skipped += 1
            continue
        rel, direction = found
        queries.append(
            EvalQuery(
                qid=f"metaqa1hop:{line_no}",
                question=question,
                terms=[
                    TermLookup(topic, "entity", True),
                    TermLookup(rel, "relation", True),
                ],
                kind="metaqa1hop",
                topic=topic,
                relation=(rel, direction),
                gold_answers=gold,
            )
        )
    return Workload(
        name="metaqa",
        partitions=partitions,
        queries=queries,
        notes=(
            "Real SimGRAG 2-party federated MetaQA KGs; 1-hop vanilla qa_test "
            "questions with the relation derived from the gold chain "
            f"({skipped} questions skipped: topic missing or no exact-relation match)."
        ),
    )


def load_webqsp(count: int) -> Workload:
    partitions = _load_party_pickles(
        {
            f"party_{pid}": SIMGRAG / f"data/webqsp/federated/party_{pid}/party.pkl"
            for pid in range(5)
        }
    )
    rog_path = SIMGRAG / "data/raw/rog_webqsp/test.jsonl"
    queries: list[EvalQuery] = []
    with rog_path.open() as handle:
        for line in handle:
            if len(queries) >= count:
                break
            record = json.loads(line)
            q_entities = [str(e) for e in record.get("q_entity") or []]
            a_entities = [str(e) for e in record.get("a_entity") or []]
            if not q_entities:
                continue
            queries.append(
                EvalQuery(
                    qid=f"webqsp:{record['id']}",
                    question=str(record["question"]),
                    terms=[TermLookup(e, "entity", True) for e in q_entities],
                    kind="retrieval",
                    gold_answers=a_entities,
                )
            )
    return Workload(
        name="webqsp",
        partitions=partitions,
        queries=queries,
        notes=(
            "Real SimGRAG 5-party federated WebQSP KG (a genuine N=5 data "
            "federation); RoG WebQSP test questions: private lookup of each "
            "gold topic entity, answer-entity universe coverage reported."
        ),
    )


def load_lcquad2(count: int) -> Workload:
    payload = json.loads((ROOT / "data/lc_quad2/raw/data/test.json").read_text())
    graph: dict[str, dict[str, set]] = {}
    for item in payload:
        sparql = item.get("sparql_wikidata") or ""
        for m in WD_PAIR_RE.finditer(sparql):
            entity = m.group(1) or m.group(4)
            relation = m.group(2) or m.group(3)
            if entity and relation:
                graph.setdefault(entity, {}).setdefault(relation, set()).add(entity)
    queries: list[EvalQuery] = []
    for item in payload:
        if len(queries) >= count:
            break
        sparql = item.get("sparql_wikidata") or ""
        entities = sorted(set(WD_ENTITY_RE.findall(sparql)))
        relations = sorted(set(WD_RELATION_RE.findall(sparql)))
        if not entities or not relations:
            continue
        terms = [TermLookup(e, "entity", e in graph) for e in entities]
        terms += [TermLookup(r, "relation", True) for r in relations]
        queries.append(
            EvalQuery(
                qid=f"lcquad2:{item['uid']}",
                question=str(item.get("question") or item.get("NNQT_question")),
                terms=terms,
                kind="retrieval",
            )
        )
    partitions = _hash_split(graph, 3, "lcq2")
    return Workload(
        name="lcquad2",
        partitions=partitions,
        queries=queries,
        notes=(
            "Term-universe fixture built from all 6,046 LC-QuAD 2.0 test SPARQL "
            "queries (wd:/wdt: co-occurrence edges populate the entity/relation "
            "universes; adjacency is an artifact — no local Wikidata, so no "
            "answer derivation). Retrieval-level end-to-end only."
        ),
    )


def _hash_split(graph: dict, owners: int, tag: str) -> dict[str, dict]:
    import hashlib as _hashlib

    partitions: dict[str, dict] = {f"{tag}_owner_{i}": {} for i in range(owners)}
    for head in graph:
        bucket = int.from_bytes(
            _hashlib.sha256(str(head).encode("utf-8")).digest()[:4], "big"
        ) % owners
        partitions[f"{tag}_owner_{bucket}"][head] = {
            rel: sorted(map(str, targets)) for rel, targets in graph[head].items()
        }
    return partitions


def _owner_rows_to_graphs(base: Path, owners: int, tag: str) -> dict[str, dict]:
    partitions = {}
    for i in range(owners):
        rows = json.loads((base / f"owner_{i}.json").read_text())
        graph: dict[str, dict[str, set]] = {}
        for row in rows:
            graph.setdefault(str(row["source"]), {}).setdefault(
                str(row["relation"]), set()
            ).add(str(row["target"]))
        partitions[f"{tag}_owner_{i}"] = {
            head: {rel: sorted(ts) for rel, ts in rels.items()}
            for head, rels in graph.items()
        }
    return partitions


def load_kqapro(count: int) -> Workload:
    base = ROOT / "data/kqa_pro/relation_fixture"
    partitions = _owner_rows_to_graphs(base / "full", 3, "kqa")
    queries_raw = json.loads((base / "compatible_closure/queries.json").read_text())
    expected = json.loads((base / "compatible_closure/expected_answers.json").read_text())
    queries: list[EvalQuery] = []
    for spec, gold in list(zip(queries_raw, expected))[:count]:
        source, rel1, rel2 = spec["source"], spec["relation_1"], spec["relation_2"]
        queries.append(
            EvalQuery(
                qid=f"kqapro:{gold['uid']}",
                question=gold["question"],
                terms=[
                    TermLookup(source, "entity", True),
                    TermLookup(rel1, "relation", True),
                    TermLookup(rel2, "relation", True),
                ],
                kind="chain2",
                chain=(source, rel1, rel2),
                gold_answers=list(gold.get("endpoint_ids") or []),
            )
        )
    return Workload(
        name="kqapro",
        partitions=partitions,
        queries=queries,
        notes=(
            "Full frozen KQA Pro relation graph (385,774 directed edges, "
            "3 synthetic owners from data/kqa_pro/relation_fixture/full); "
            "two-hop validation queries + endpoint gold from "
            "compatible_closure. Answers read out of the opaque adjacency "
            "after three private anchor lookups."
        ),
    )


def load_cwq(count: int) -> tuple[Workload, Workload]:
    base = ROOT / "data/cwq/mpc_fixture/q25_closure"
    partitions = _owner_rows_to_graphs(base, 3, "cwq")
    validation = json.loads((base / "cleartext_validation.json").read_text())["records"]
    closure_queries: list[EvalQuery] = []
    for record in validation:
        spec = record["query"]
        closure_queries.append(
            EvalQuery(
                qid=f"cwq-closure:{record['uid']}",
                question=record["question"],
                terms=[
                    TermLookup(str(spec["source"]), "entity", True),
                    TermLookup(str(spec["relation_1"]), "relation", True),
                    TermLookup(str(spec["relation_2"]), "relation", True),
                ],
                kind="chain2",
                chain=(str(spec["source"]), str(spec["relation_1"]), str(spec["relation_2"])),
                gold_answers=[str(g) for g in record.get("groundtruths") or []],
            )
        )
    closure = Workload(
        name="cwq-closure",
        partitions=partitions,
        queries=closure_queries,
        notes=(
            "CWQ 25-query two-hop closure fixture (data/cwq/mpc_fixture/"
            "q25_closure, 3 owners, 4,625 edges); gold = cleartext_validation "
            "groundtruth labels. Known fixture caps: fanout_per_owner=8, "
            "303 pruned edges."
        ),
    )

    rog_path = ROOT / "data/cwq/raw/rog_cwq_test.jsonl"
    rog_count = max(count - len(closure_queries), 0)
    union: dict[str, dict[str, set]] = {}
    rog_queries: list[EvalQuery] = []
    with rog_path.open() as handle:
        for line in handle:
            if len(rog_queries) >= rog_count:
                break
            record = json.loads(line)
            graph = record.get("graph") or []
            q_entities = [str(e) for e in record.get("q_entity") or []]
            a_entities = [str(e) for e in record.get("a_entity") or []]
            if not graph or not q_entities:
                continue
            for triple in graph:
                if len(triple) != 3:
                    continue
                h, r, t = (str(x) for x in triple)
                union.setdefault(h, {}).setdefault(r, set()).add(t)
            rog_queries.append(
                EvalQuery(
                    qid=f"cwq-rog:{record['id']}",
                    question=str(record["question"]),
                    terms=[TermLookup(e, "entity", True) for e in q_entities],
                    kind="retrieval",
                    gold_answers=a_entities,
                )
            )
    rog = Workload(
        name="cwq-rog",
        partitions=_hash_split(union, 3, "rog"),
        queries=rog_queries,
        notes=(
            f"Union KG of the first {len(rog_queries)} RoG CWQ test subgraphs "
            "(3 hash-split owners); per query: private lookup of each gold "
            "topic entity; answer-entity universe coverage reported."
        ),
    )
    return closure, rog


# --------------------------------------------------------------------------
# Evaluation engine
# --------------------------------------------------------------------------


class DatasetHarness:
    def __init__(
        self,
        workload: Workload,
        party_count: int,
        out_root: Path,
        repeats: int = 1,
        transport: str = "inprocess",
    ):
        self.workload = workload
        self.party_count = party_count
        self.threshold = honest_majority_threshold(party_count)
        self.ids = HmacIdProvider(EVAL_KEY)
        self.out_root = out_root
        self.repeats = max(1, repeats)
        self.transport = transport
        self.store_root: Path | None = None
        self.stores: list[MultipartyFssEvaluatorStore] = []
        self.services: list[MultipartyFssEvaluatorService] = []
        self.clients: list[SocketEvaluatorClient] = []
        self.server_processes: list[subprocess.Popen] = []
        self.universes: dict[str, UniverseDomain] = {}
        self.digests: dict[str, str] = {}
        self.combined_adjacency: dict[str, dict[str, set]] = {}
        self.combined_reverse: dict[str, dict[str, set]] = {}
        self.setup_stats: dict[str, object] = {}

    def build_stores(self) -> None:
        start = time.perf_counter()
        snapshots = []
        for party_id, graph in sorted(self.workload.partitions.items()):
            index = SecurePartyIndex.from_plain_graph(
                party_id, graph, self.workload.types.get(party_id), self.ids
            )
            snapshots.append(OpaqueIndexSnapshot.from_secure_index(index, self.ids))
        build_seconds = time.perf_counter() - start

        self.store_root = self.out_root / (
            f"stores_{self.workload.name}_n{self.party_count}"
        )
        evaluator_ids = [f"mp_fss_{i}" for i in range(self.party_count)]
        start = time.perf_counter()
        replicate_opaque_snapshots_multiparty(
            snapshots, evaluator_ids, self.store_root, threshold=self.threshold
        )
        replicate_seconds = time.perf_counter() - start
        start = time.perf_counter()
        self.stores = [
            MultipartyFssEvaluatorStore.load(
                self.store_root / eid, expected_evaluator_id=eid
            )
            for eid in evaluator_ids
        ]
        load_seconds = time.perf_counter() - start
        self.services = [MultipartyFssEvaluatorService(s) for s in self.stores]

        for domain in ("entity", "relation"):
            universe = self.stores[0].universe(domain)
            self.universes[domain] = universe
            self.digests[domain] = universe.digest()
        for snapshot in self.stores[0].index.snapshots:
            for head, rels in snapshot.adjacency.items():
                for rel, targets in rels.items():
                    self.combined_adjacency.setdefault(head, {}).setdefault(
                        rel, set()
                    ).update(targets)
            for head, rels in snapshot.reverse_adjacency.items():
                for rel, sources in rels.items():
                    self.combined_reverse.setdefault(head, {}).setdefault(
                        rel, set()
                    ).update(sources)
        store_bytes = sum(
            p.stat().st_size for p in self.store_root.rglob("*") if p.is_file()
        )
        self.setup_stats = {
            "snapshot_build_s": round(build_seconds, 3),
            "replicate_s": round(replicate_seconds, 3),
            "store_load_s": round(load_seconds, 3),
            "store_bytes_total": store_bytes,
            "partitions": len(snapshots),
            "entity_universe": self.universes["entity"].size,
            "entity_domain_bits": self.universes["entity"].domain_bits,
            "relation_universe": self.universes["relation"].size,
            "relation_domain_bits": self.universes["relation"].domain_bits,
        }

    def start_servers(self) -> None:
        serve_tool = ROOT / "multiparty_fss/tools/serve_multiparty_evaluator.py"
        for index in range(self.party_count):
            evaluator_id = f"mp_fss_{index}"
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(serve_tool),
                    "--store",
                    str(self.store_root / evaluator_id),
                    "--evaluator-id",
                    evaluator_id,
                    "--port",
                    "0",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=ROOT,
            )
            ready = process.stdout.readline().strip()
            if not ready.startswith("READY "):
                raise RuntimeError(
                    f"evaluator server {evaluator_id} failed to start: "
                    f"{ready!r} / {process.stderr.read()[:400]}"
                )
            port = int(ready.split()[1])
            self.server_processes.append(process)
            self.clients.append(SocketEvaluatorClient("127.0.0.1", port))

    def stop_servers(self) -> None:
        for process in self.server_processes:
            process.terminate()
        for process in self.server_processes:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
        self.server_processes = []
        self.clients = []

    def _encode(self, label: str, domain: str) -> str:
        return (
            self.ids.entity_id(label) if domain == "entity" else self.ids.relation_id(label)
        )

    def _dispatch_inprocess(self, requests: list[MpFssEvaluatorRequest]):
        responses, eval_seconds = [], []
        for index, request in enumerate(requests):
            start = time.perf_counter()
            responses.append(self.services[index].evaluate(request))
            eval_seconds.append(time.perf_counter() - start)
        return responses, max(eval_seconds), sum(eval_seconds)

    def _dispatch_socket(self, requests: list[MpFssEvaluatorRequest]):
        payloads = [request.to_dict() for request in requests]
        responses: list[MpFssEvaluatorResponse | None] = [None] * len(requests)
        errors: list[Exception] = []

        def worker(index: int) -> None:
            try:
                raw = self.clients[index].evaluate(payloads[index])
                responses[index] = MpFssEvaluatorResponse.from_dict(raw)
            except Exception as exc:  # collected and re-raised below
                errors.append(exc)

        start = time.perf_counter()
        threads = [
            threading.Thread(target=worker, args=(index,))
            for index in range(len(requests))
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        wall = time.perf_counter() - start
        if errors:
            raise errors[0]
        return list(responses), wall, wall

    def _lookup_once(self, label: str, domain: str, request_id: str):
        universe = self.universes[domain]
        alpha_id = self._encode(label, domain)
        rank = universe.rank_of(alpha_id)
        present = rank is not None

        start = time.perf_counter()
        key_shares = generate(
            rank if present else 0,
            1 if present else 0,
            self.party_count,
            self.threshold,
            domain_bits=universe.domain_bits,
            domain_binding=self.digests[domain],
        )
        keygen_s = time.perf_counter() - start

        requests = [
            MpFssEvaluatorRequest(
                request_id=request_id,
                domain=domain,
                evaluator_id=f"mp_fss_{index}",
                party_index=index,
                party_count=self.party_count,
                threshold=self.threshold,
                key_share=key_shares[index],
                projection=None,
            )
            for index in range(self.party_count)
        ]
        if self.transport == "socket":
            responses, eval_critical, eval_total = self._dispatch_socket(requests)
        else:
            responses, eval_critical, eval_total = self._dispatch_inprocess(requests)

        start = time.perf_counter()
        combined = MpFssCoordinator(self.party_count, self.threshold).combine(
            responses, expected_request_id=request_id
        )
        combine_s = time.perf_counter() - start
        return (
            alpha_id,
            present,
            combined,
            {
                "keygen_ms": keygen_s * 1e3,
                "eval_ms_critical": eval_critical * 1e3,
                "eval_ms_total": eval_total * 1e3,
                "combine_ms": combine_s * 1e3,
                "total_ms_parallel": (keygen_s + eval_critical + combine_s) * 1e3,
            },
            key_shares,
            responses,
        )

    def lookup(self, label: str, domain: str, request_id: str, measure_sizes: bool):
        """Median-of-repeats timed private lookup; correctness from rep 0."""
        timings: list[dict] = []
        first = None
        for rep in range(self.repeats):
            result = self._lookup_once(label, domain, f"{request_id}-r{rep}")
            timings.append(result[3])
            if rep == 0:
                first = result
        alpha_id, present, combined, _, key_shares, responses = first
        universe = self.universes[domain]
        nonzero = {
            universe.points[i]: value
            for i, value in enumerate(combined.values)
            if value != 0
        }
        hit = bool(nonzero)
        correct = (nonzero == {alpha_id: 1}) if present else (nonzero == {})
        median_timing = {
            key: statistics.median(t[key] for t in timings) for key in timings[0]
        }
        sizes = None
        if measure_sizes:
            sizes = {
                "key_share_json_bytes": len(json.dumps(key_shares[0].to_dict())),
                "response_json_bytes": len(json.dumps(responses[0].to_dict())),
            }
        return {
            "label_domain": domain,
            "universe": universe.size,
            "present": present,
            "hit": hit,
            "correct": correct,
            "retrieved": sorted(nonzero),
            "alpha_id": alpha_id,
            **median_timing,
            "repeats": self.repeats,
            "sizes": sizes,
        }

    def derive_answers(self, query: EvalQuery, lookups: list[dict]) -> dict | None:
        if query.kind == "metaqa1hop":
            entity_ok = lookups[0]["correct"] and lookups[0]["present"]
            relation_ok = lookups[1]["correct"] and lookups[1]["present"]
            rel_label, direction = query.relation
            topic_id = self._encode(query.topic, "entity")
            rel_id = self._encode(rel_label, "relation")
            index = (
                self.combined_adjacency if direction == "out" else self.combined_reverse
            )
            retrieved = set(index.get(topic_id, {}).get(rel_id, set()))
            gold_ids = {self._encode(g, "entity") for g in query.gold_answers}
            return {
                "answers_derivable": entity_ok and relation_ok,
                "retrieved_count": len(retrieved),
                "gold_count": len(gold_ids),
                "exact_match": retrieved == gold_ids,
                "coverage": (
                    len(retrieved & gold_ids) / len(gold_ids) if gold_ids else None
                ),
            }
        if query.kind == "chain2":
            source, rel1, rel2 = query.chain
            anchors_ok = all(l["correct"] and l["present"] for l in lookups[:3])
            source_id = self._encode(source, "entity")
            rel1_id = self._encode(rel1, "relation")
            rel2_id = self._encode(rel2, "relation")
            hop1 = set(self.combined_adjacency.get(source_id, {}).get(rel1_id, set()))
            hop2 = set()
            for mid in hop1:
                hop2 |= set(self.combined_adjacency.get(mid, {}).get(rel2_id, set()))
            gold_ids = {self._encode(g, "entity") for g in query.gold_answers or []}
            return {
                "answers_derivable": anchors_ok,
                "hop1_count": len(hop1),
                "retrieved_count": len(hop2),
                "gold_count": len(gold_ids),
                "exact_match": hop2 == gold_ids if gold_ids else None,
                "coverage": (
                    len(hop2 & gold_ids) / len(gold_ids) if gold_ids else None
                ),
            }
        if query.kind == "retrieval" and query.gold_answers:
            universe = self.universes["entity"]
            in_universe = sum(
                1
                for g in query.gold_answers
                if universe.rank_of(self._encode(g, "entity")) is not None
            )
            return {
                "answers_derivable": None,
                "gold_count": len(query.gold_answers),
                "gold_in_universe": in_universe,
                "coverage": in_universe / len(query.gold_answers),
                "exact_match": None,
            }
        return None

    def run(self) -> dict:
        self.build_stores()
        if self.transport == "socket":
            self.start_servers()
        try:
            # Warm-up (untimed): one lookup per domain.
            for domain in ("entity", "relation"):
                if self.universes[domain].size:
                    self._lookup_once("__warmup__", domain, "warmup")

            per_query = []
            wall_start = time.perf_counter()
            sizes_by_domain: dict[str, dict] = {}
            for q_index, query in enumerate(self.workload.queries):
                lookups = []
                for t_index, term in enumerate(query.terms):
                    measure = term.domain not in sizes_by_domain
                    result = self.lookup(
                        term.label,
                        term.domain,
                        request_id=f"{self.workload.name}-{q_index}-{t_index}",
                        measure_sizes=measure,
                    )
                    result["expected_present"] = term.expect_present
                    if measure and result["sizes"]:
                        sizes_by_domain[term.domain] = result["sizes"]
                    lookups.append(result)
                answers = self.derive_answers(query, lookups)
                per_query.append(
                    {
                        "qid": query.qid,
                        "question": query.question,
                        "kind": query.kind,
                        "lookups": lookups,
                        "answers": answers,
                    }
                )
            controls = []
            for i in range(NEGATIVE_CONTROLS):
                for domain in ("entity", "relation"):
                    result = self.lookup(
                        f"__mpfss_absent_control_{i}__",
                        domain,
                        request_id=f"{self.workload.name}-neg-{domain}-{i}",
                        measure_sizes=False,
                    )
                    controls.append(
                        {
                            "domain": domain,
                            "correct_miss": result["correct"] and not result["hit"],
                        }
                    )
            wall_seconds = time.perf_counter() - wall_start
        finally:
            if self.transport == "socket":
                self.stop_servers()

        return {
            "workload": self.workload.name,
            "notes": self.workload.notes,
            "party_count": self.party_count,
            "threshold": self.threshold,
            "transport": self.transport,
            "repeats": self.repeats,
            "environment": environment_info(),
            "setup": self.setup_stats,
            "sizes_by_domain": sizes_by_domain,
            "queries": per_query,
            "negative_controls": controls,
            "query_phase_wall_s": round(wall_seconds, 3),
        }


def environment_info() -> dict:
    return {
        "python": platform.python_version(),
        "numpy": np.__version__,
        "machine": platform.machine(),
        "processor_hint": "Intel Xeon Gold 6136 @ 3.00GHz (single-core usage)",
        "note": "in-process transport uses a parallel-evaluator latency model "
        "(max over N); socket transport measures real parallel round trips",
    }


def _pct(values, q):
    if not values:
        return None
    values = sorted(values)
    rank = min(len(values) - 1, max(0, int(round(q * (len(values) - 1)))))
    return values[rank]


def summarize(run: dict) -> dict:
    lookups = [l for q in run["queries"] for l in q["lookups"]]
    present = [l for l in lookups if l["present"]]
    answers = [q["answers"] for q in run["queries"] if q["answers"]]

    def stage_stats(pool, name):
        vals = [l[name] for l in pool]
        if not vals:
            return None
        return {
            "mean": round(statistics.mean(vals), 3),
            "p50": round(_pct(vals, 0.50), 3),
            "p95": round(_pct(vals, 0.95), 3),
        }

    def domain_block(domain):
        pool = [l for l in lookups if l["label_domain"] == domain]
        if not pool:
            return None
        return {
            "lookups": len(pool),
            "keygen": stage_stats(pool, "keygen_ms"),
            "eval_critical": stage_stats(pool, "eval_ms_critical"),
            "combine": stage_stats(pool, "combine_ms"),
            "total_parallel_model": stage_stats(pool, "total_ms_parallel"),
        }

    exact_flags = [a["exact_match"] for a in answers if a.get("exact_match") is not None]
    coverages = [a["coverage"] for a in answers if a.get("coverage") is not None]
    return {
        "workload": run["workload"],
        "party_count": run["party_count"],
        "threshold": run["threshold"],
        "transport": run["transport"],
        "repeats": run["repeats"],
        "queries": len(run["queries"]),
        "term_lookups": len(lookups),
        "lookups_present": len(present),
        "retrieval_correct_rate": round(
            sum(1 for l in lookups if l["correct"]) / len(lookups), 4
        ),
        "present_hit_rate": round(
            sum(1 for l in present if l["hit"]) / len(present), 4
        )
        if present
        else None,
        "negative_controls_pass": all(
            c["correct_miss"] for c in run["negative_controls"]
        ),
        "latency_ms_by_domain": {
            "entity": domain_block("entity"),
            "relation": domain_block("relation"),
        },
        "answer_metrics": {
            "queries_with_answer_stage": len(answers),
            "exact_match_rate": round(sum(exact_flags) / len(exact_flags), 4)
            if exact_flags
            else None,
            "mean_coverage": round(statistics.mean(coverages), 4) if coverages else None,
        },
        "setup": run["setup"],
        "sizes_by_domain": run["sizes_by_domain"],
        "query_phase_wall_s": run["query_phase_wall_s"],
    }


def build_workloads(datasets: set[str], queries: int, party_count: int, scaling: bool):
    workloads: list[tuple[Workload, int]] = []
    if "metaqa" in datasets:
        workloads.append((load_metaqa(queries), party_count))
    if "webqsp" in datasets:
        workloads.append((load_webqsp(queries), 5))  # real 5-party federation
    if "lcquad2" in datasets:
        workloads.append((load_lcquad2(queries), party_count))
    if "kqapro" in datasets:
        workloads.append((load_kqapro(queries), party_count))
    if "cwq" in datasets:
        closure, rog = load_cwq(queries)
        workloads.append((closure, party_count))
        workloads.append((rog, party_count))
    if scaling and "metaqa" in datasets:
        scaled = load_metaqa(20)
        for n in (5, 7):
            workloads.append(
                (
                    Workload(
                        name=f"metaqa-n{n}",
                        partitions=scaled.partitions,
                        queries=scaled.queries,
                        notes=f"MetaQA scaling rerun at N={n} (20 queries).",
                    ),
                    n,
                )
            )
    return workloads


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset",
        action="append",
        choices=("metaqa", "webqsp", "lcquad2", "kqapro", "cwq", "all"),
        required=True,
    )
    parser.add_argument("--queries", type=int, default=50)
    parser.add_argument("--party-count", type=int, default=3)
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--transport", choices=("inprocess", "socket"), default="inprocess")
    parser.add_argument("--scaling", action="store_true")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    datasets = set(args.dataset)
    if "all" in datasets:
        datasets = {"metaqa", "webqsp", "lcquad2", "kqapro", "cwq"}
    args.out.mkdir(parents=True, exist_ok=True)

    summaries = []
    for workload, party_count in build_workloads(
        datasets, args.queries, args.party_count, args.scaling
    ):
        print(
            f"[{workload.name}] N={party_count} transport={args.transport} "
            f"queries={len(workload.queries)} partitions={len(workload.partitions)}",
            flush=True,
        )
        harness = DatasetHarness(
            workload,
            party_count,
            args.out,
            repeats=args.repeats,
            transport=args.transport,
        )
        run = harness.run()
        tag = f"{workload.name}_n{party_count}_{args.transport}"
        (args.out / f"{tag}_full.json").write_text(json.dumps(run, indent=1))
        summary = summarize(run)
        summaries.append(summary)
        (args.out / f"{tag}_summary.json").write_text(json.dumps(summary, indent=2))
        print(json.dumps(summary, indent=2), flush=True)
    (args.out / f"all_summaries_{args.transport}.json").write_text(
        json.dumps(summaries, indent=2)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
