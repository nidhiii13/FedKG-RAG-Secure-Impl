"""Multi-party FSS evaluator store and evaluation service.

One instance = one evaluator role. The store loads the N-party manifest
written by multiparty_fss/replication.py, re-verifies every snapshot digest,
and refuses to serve any request whose identity, topology, construction,
parameter, or universe binding does not match — the full matrix in
research_and_design.md section 6.6.

The evaluator never sees alpha or beta: it receives only its own key share,
evaluates it over the public shared universe (rank domain), and returns raw
GF(2)^64 output shares (dense) or XOR-projected candidate-slot shares. A
single evaluator's output share is never a match decision.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from src.party.opaque_index_snapshot import OpaqueIndexSnapshot, ReplicatedEvaluatorIndex

from multiparty_fss.domain import UniverseDomain
from multiparty_fss.errors import RequestValidationError, StoreError
from multiparty_fss.evaluate import evaluate_universe
from multiparty_fss.keyshare import DOMAIN_BINDING_RAW
from multiparty_fss.params import (
    CONSTRUCTION_ID,
    MAX_PARTIES,
    MIN_PARTIES,
    WIRE_VERSION_MANIFEST,
)
from multiparty_fss.projection import XorCandidateProjection
from multiparty_fss.requests import (
    EVALUATION_DOMAINS,
    MpFssEvaluatorRequest,
    MpFssEvaluatorResponse,
)


@dataclass(frozen=True)
class MultipartyFssEvaluatorStore:
    evaluator_id: str
    party_index: int
    party_count: int
    threshold: int
    evaluator_ids: tuple[str, ...]
    index: ReplicatedEvaluatorIndex
    # Per-domain universe cache. The snapshot set is immutable after load, so
    # the sorted/validated universe (and its digest) is computed once per
    # domain instead of on every request.
    _universe_cache: dict = field(default_factory=dict, compare=False, repr=False)

    @classmethod
    def load(
        cls, root: str | Path, expected_evaluator_id: str | None = None
    ) -> "MultipartyFssEvaluatorStore":
        store_root = Path(root)
        try:
            manifest = json.loads((store_root / "manifest.json").read_text())
        except FileNotFoundError as exc:
            raise StoreError(f"evaluator store has no manifest: {store_root}") from exc
        except json.JSONDecodeError as exc:
            raise StoreError("evaluator manifest is not valid JSON") from exc
        if not isinstance(manifest, dict):
            raise StoreError("evaluator manifest must be a JSON object")
        if manifest.get("version") != WIRE_VERSION_MANIFEST:
            raise StoreError(
                f"unsupported evaluator manifest version: {manifest.get('version')!r} "
                "(two-party manifests are rejected on the multi-party path)"
            )
        if manifest.get("construction") != CONSTRUCTION_ID:
            raise StoreError(
                f"unsupported construction in manifest: {manifest.get('construction')!r}"
            )
        evaluator_id = manifest.get("evaluator_id")
        party_index = manifest.get("party_index")
        party_count = manifest.get("party_count")
        threshold = manifest.get("threshold")
        evaluator_ids = manifest.get("evaluator_ids")
        records = manifest.get("snapshots")
        if not isinstance(evaluator_id, str) or not evaluator_id:
            raise StoreError("evaluator manifest requires evaluator_id")
        for name, value in (
            ("party_index", party_index),
            ("party_count", party_count),
            ("threshold", threshold),
        ):
            if not isinstance(value, int) or isinstance(value, bool):
                raise StoreError(f"evaluator manifest {name} must be an integer")
        if not MIN_PARTIES <= party_count <= MAX_PARTIES:
            raise StoreError(
                f"evaluator manifest party_count must be in "
                f"[{MIN_PARTIES}, {MAX_PARTIES}]"
            )
        if not 1 <= threshold <= party_count - 1:
            raise StoreError("evaluator manifest threshold must satisfy 1 <= t <= N-1")
        if (
            not isinstance(evaluator_ids, list)
            or len(evaluator_ids) != party_count
            or len(set(evaluator_ids)) != party_count
            or not all(isinstance(item, str) and item for item in evaluator_ids)
        ):
            raise StoreError(
                "evaluator manifest requires party_count unique evaluator_ids"
            )
        if not 0 <= party_index < party_count:
            raise StoreError("evaluator manifest party_index out of range")
        if evaluator_ids[party_index] != evaluator_id:
            raise StoreError(
                "evaluator manifest party_index does not match evaluator_ids order"
            )
        if expected_evaluator_id is not None and evaluator_id != expected_evaluator_id:
            raise StoreError("evaluator store identity does not match configured role")
        if not isinstance(records, list) or not records:
            raise StoreError("evaluator manifest requires snapshot records")

        snapshots = []
        for record in records:
            if not isinstance(record, dict):
                raise StoreError("invalid evaluator snapshot record")
            relative_path = record.get("relative_path")
            expected_digest = record.get("digest")
            expected_partition = record.get("partition_id")
            if not all(
                isinstance(value, str) and value
                for value in (relative_path, expected_digest, expected_partition)
            ):
                raise StoreError(
                    "snapshot records require path, digest, and partition ID"
                )
            path = (store_root / relative_path).resolve()
            if store_root.resolve() not in path.parents:
                raise StoreError("snapshot path escapes evaluator store")
            snapshot = OpaqueIndexSnapshot.from_json(path)
            if snapshot.partition_id != expected_partition:
                raise StoreError("snapshot partition ID does not match manifest")
            if snapshot.digest() != expected_digest:
                raise StoreError("snapshot digest does not match manifest")
            snapshots.append(snapshot)
        return cls(
            evaluator_id=evaluator_id,
            party_index=party_index,
            party_count=party_count,
            threshold=threshold,
            evaluator_ids=tuple(evaluator_ids),
            index=ReplicatedEvaluatorIndex(tuple(snapshots)),
        )

    def points_for(self, domain: str) -> list[str]:
        if domain == "entity":
            return self.index.entity_points
        if domain == "relation":
            return self.index.relation_points
        if domain == "type":
            return sorted(
                {
                    type_id
                    for snapshot in self.index.snapshots
                    for type_id in snapshot.type_index
                }
            )
        if domain == "frontier":
            return self.index.frontier_points
        if domain == "relation_bucket":
            return self.index.relation_bucket_points
        if domain == "entity_bucket":
            return self.index.entity_bucket_points
        raise RequestValidationError(f"unsupported evaluation domain: {domain!r}")

    def universe(self, domain: str) -> UniverseDomain:
        if domain not in EVALUATION_DOMAINS:
            raise RequestValidationError(f"unsupported evaluation domain: {domain!r}")
        cached = self._universe_cache.get(domain)
        if cached is None:
            cached = UniverseDomain.from_points(self.points_for(domain))
            self._universe_cache[domain] = cached
        return cached


@dataclass(frozen=True)
class MultipartyFssEvaluatorService:
    store: MultipartyFssEvaluatorStore

    def evaluate(self, request: MpFssEvaluatorRequest) -> MpFssEvaluatorResponse:
        store = self.store
        if not request.request_id:
            raise RequestValidationError("request_id must not be empty")
        if request.evaluator_id != store.evaluator_id:
            raise RequestValidationError(
                "request is addressed to a different evaluator"
            )
        if request.party_index != store.party_index:
            raise RequestValidationError(
                "request party_index does not match this evaluator's manifest"
            )
        if request.party_count != store.party_count:
            raise RequestValidationError(
                "request party_count does not match this evaluator's manifest"
            )
        if request.threshold != store.threshold:
            raise RequestValidationError(
                "request threshold does not match this evaluator's manifest"
            )
        key_share = request.key_share
        # MpFssEvaluatorRequest.from_dict already binds key<->request N/t/index;
        # re-check here so programmatically built requests get the same guarantees.
        if key_share.party_index != store.party_index:
            raise RequestValidationError(
                "key share party_index does not match this evaluator"
            )
        if key_share.params.party_count != store.party_count:
            raise RequestValidationError("key share party_count does not match store")
        if key_share.params.threshold != store.threshold:
            raise RequestValidationError("key share threshold does not match store")

        universe = store.universe(request.domain)
        digest = universe.digest()
        if key_share.domain_binding == DOMAIN_BINDING_RAW:
            raise RequestValidationError(
                "key share is not bound to a universe; the evaluator service "
                "requires domain_binding to equal its universe digest"
            )
        if key_share.domain_binding != digest:
            raise RequestValidationError(
                "key share universe binding does not match this evaluator's store"
            )
        if key_share.params.domain_bits != universe.domain_bits:
            raise RequestValidationError(
                "key share domain_bits does not match the shared universe size"
            )

        shares_vector = evaluate_universe(key_share, universe.size)
        shares = [int(value) for value in shares_vector]

        if request.projection is None:
            return MpFssEvaluatorResponse(
                request_id=request.request_id,
                evaluator_id=store.evaluator_id,
                party_index=store.party_index,
                party_count=store.party_count,
                threshold=store.threshold,
                params_id=key_share.params.params_id(),
                keygen_id=key_share.keygen_id,
                domain=request.domain,
                universe_digest=digest,
                payload_kind="dense",
                point_count=universe.size,
                value_shares=tuple(shares),
                projection_digest=None,
                slot_handles=None,
                candidate_slot_shares=None,
            )

        projection = XorCandidateProjection.from_mapping(request.projection)
        slot_shares = projection.project(list(universe.points), shares)
        return MpFssEvaluatorResponse(
            request_id=request.request_id,
            evaluator_id=store.evaluator_id,
            party_index=store.party_index,
            party_count=store.party_count,
            threshold=store.threshold,
            params_id=key_share.params.params_id(),
            keygen_id=key_share.keygen_id,
            domain=request.domain,
            universe_digest=digest,
            payload_kind="projected",
            point_count=None,
            value_shares=None,
            projection_digest=projection.digest(),
            slot_handles=projection.slot_handles,
            candidate_slot_shares=tuple(slot_shares),
        )
