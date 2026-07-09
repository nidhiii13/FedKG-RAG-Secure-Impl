"""Private semantic bucket routing for relation candidates."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, Mapping, Sequence

from src.crypto.dpf import DpfBackend, DpfKeyShare
from src.crypto.dpf_domain import DPF_MODULUS
from src.crypto.hmac_ids import HmacIdProvider
from src.semantic.entity_buckets import EntitySemanticIndex, entity_bucket_names
from src.semantic.lsh import HashingTextEmbedder, TextEmbedder, simgrag_distance
from src.semantic.relation_buckets import RelationSemanticIndex, SemanticBucketMode, relation_bucket_names


@dataclass(frozen=True)
class SemanticBucketRequest:
    label: str
    bucket_token: str
    penalty: float
    query_vector: tuple[float, ...]
    key_shares: Mapping[str, DpfKeyShare]


@dataclass(frozen=True)
class SemanticBucketEvalShares:
    party_id: str
    label: str
    bucket_token: str
    eval_shares: Dict[str, int]


@dataclass(frozen=True)
class SemanticRelationRouting:
    relation_ids_by_label: Dict[str, set[str]]
    matched_bucket_tokens_by_label: Dict[str, set[str]]
    relation_penalties_by_label: Dict[str, Dict[str, float]]


@dataclass(frozen=True)
class SemanticEntityRouting:
    entity_ids_by_label: Dict[str, set[str]]
    matched_bucket_tokens_by_label: Dict[str, set[str]]
    entity_penalties_by_label: Dict[str, Dict[str, float]]


@dataclass(frozen=True)
class PrivateSemanticRelationRouter:
    ids: HmacIdProvider
    backend: DpfBackend
    party_ids: Sequence[str]
    bucket_mode: SemanticBucketMode = "hybrid"
    alias_penalty: float = 0.25
    lsh_penalty: float = 0.5
    embedder: TextEmbedder | None = None
    modulus: int = DPF_MODULUS

    def route(
        self,
        relation_labels: Sequence[str],
        indexes: Mapping[str, RelationSemanticIndex],
    ) -> SemanticRelationRouting:
        universe = sorted({token for index in indexes.values() for token in index.tokens})
        requests = self._requests(relation_labels)
        eval_batches = [
            self._evaluate(party_id, request, universe)
            for request in requests
            for party_id in self.party_ids
        ]
        matched_by_label = self._reconstruct(eval_batches)
        query_vectors = self._query_vectors(requests)
        relation_ids_by_label: Dict[str, set[str]] = {}
        relation_penalties_by_label: Dict[str, Dict[str, float]] = {}
        for label, tokens in matched_by_label.items():
            relation_ids, relation_penalties = self._relations_for_tokens(
                indexes.values(),
                tokens,
                query_vectors[label],
                self.lsh_penalty,
            )
            relation_ids_by_label[label] = relation_ids
            relation_penalties_by_label[label] = relation_penalties
        return SemanticRelationRouting(
            relation_ids_by_label=relation_ids_by_label,
            matched_bucket_tokens_by_label=matched_by_label,
            relation_penalties_by_label=relation_penalties_by_label,
        )

    def _requests(self, relation_labels: Sequence[str]) -> list[SemanticBucketRequest]:
        requests: list[SemanticBucketRequest] = []
        embedder = self.embedder or HashingTextEmbedder()
        for label in relation_labels:
            query_vector = tuple(embedder.embed(label))
            bucket_names = relation_bucket_names(label, mode=self.bucket_mode, embedder=embedder)
            for bucket_name in bucket_names:
                token = self.ids.relation_bucket_id(bucket_name)
                generated = self.backend.gen(token, beta=1, party_ids=self.party_ids)
                requests.append(
                    SemanticBucketRequest(
                        label=label,
                        bucket_token=token,
                        penalty=self._bucket_penalty(bucket_name),
                        query_vector=query_vector,
                        key_shares=generated,
                    )
                )
        return requests

    def _evaluate(
        self,
        party_id: str,
        request: SemanticBucketRequest,
        universe: Sequence[str],
    ) -> SemanticBucketEvalShares:
        key_share = request.key_shares[party_id]
        eval_many = getattr(self.backend, "eval_many", None)
        if callable(eval_many):
            values = eval_many(key_share, universe)
        else:
            values = [self.backend.eval(key_share, point) for point in universe]
        return SemanticBucketEvalShares(
            party_id=party_id,
            label=request.label,
            bucket_token=request.bucket_token,
            eval_shares=dict(zip(universe, values)),
        )

    def _reconstruct(self, eval_batches: Iterable[SemanticBucketEvalShares]) -> Dict[str, set[str]]:
        grouped: Dict[tuple[str, str], Dict[str, SemanticBucketEvalShares]] = {}
        for batch in eval_batches:
            grouped.setdefault((batch.label, batch.bucket_token), {})[batch.party_id] = batch

        matched_by_label: Dict[str, set[str]] = {}
        for (label, _), by_party in grouped.items():
            missing = set(self.party_ids) - set(by_party)
            if missing:
                raise ValueError(f"Missing semantic eval shares for parties: {sorted(missing)}")
            candidate_tokens = set()
            for batch in by_party.values():
                candidate_tokens.update(batch.eval_shares)
            for token in candidate_tokens:
                values = []
                for party_id in self.party_ids:
                    party_values = by_party[party_id].eval_shares
                    if token not in party_values:
                        break
                    values.append(party_values[token])
                else:
                    if sum(values) % self.modulus != 0:
                        matched_by_label.setdefault(label, set()).add(token)
        return matched_by_label

    @staticmethod
    def _relations_for_tokens(
        indexes: Iterable[RelationSemanticIndex],
        tokens: Iterable[str],
        query_vector: Sequence[float],
        fallback_penalty: float,
    ) -> tuple[set[str], Dict[str, float]]:
        token_set = set(tokens)
        relation_ids: set[str] = set()
        relation_penalties: Dict[str, float] = {}
        for index in indexes:
            for token in token_set:
                for relation_id in index.relations_for(token):
                    relation_ids.add(relation_id)
                    candidate_vector = index.vector_for(relation_id)
                    penalty = (
                        fallback_penalty
                        if candidate_vector is None
                        else simgrag_distance(query_vector, candidate_vector)
                    )
                    relation_penalties[relation_id] = min(
                        penalty,
                        relation_penalties.get(relation_id, penalty),
                    )
        return relation_ids, relation_penalties

    @staticmethod
    def _query_vectors(requests: Iterable[SemanticBucketRequest]) -> Dict[str, tuple[float, ...]]:
        query_vectors: Dict[str, tuple[float, ...]] = {}
        for request in requests:
            query_vectors.setdefault(request.label, request.query_vector)
        return query_vectors

    def _bucket_penalty(self, bucket_name: str) -> float:
        if bucket_name.startswith("lsh:"):
            return self.lsh_penalty
        return self.alias_penalty


@dataclass(frozen=True)
class PrivateSemanticEntityRouter:
    ids: HmacIdProvider
    backend: DpfBackend
    party_ids: Sequence[str]
    bucket_mode: SemanticBucketMode = "hybrid"
    alias_penalty: float = 0.2
    lsh_penalty: float = 0.45
    embedder: TextEmbedder | None = None
    modulus: int = DPF_MODULUS

    def route(
        self,
        entity_labels: Sequence[str],
        indexes: Mapping[str, EntitySemanticIndex],
    ) -> SemanticEntityRouting:
        universe = sorted({token for index in indexes.values() for token in index.tokens})
        requests = self._requests(entity_labels)
        eval_batches = [
            self._evaluate(party_id, request, universe)
            for request in requests
            for party_id in self.party_ids
        ]
        matched_by_label = self._reconstruct(eval_batches)
        query_vectors = self._query_vectors(requests)
        entity_ids_by_label: Dict[str, set[str]] = {}
        entity_penalties_by_label: Dict[str, Dict[str, float]] = {}
        for label, tokens in matched_by_label.items():
            entity_ids, entity_penalties = self._entities_for_tokens(
                indexes.values(),
                tokens,
                query_vectors[label],
                self.lsh_penalty,
            )
            entity_ids_by_label[label] = entity_ids
            entity_penalties_by_label[label] = entity_penalties
        return SemanticEntityRouting(
            entity_ids_by_label=entity_ids_by_label,
            matched_bucket_tokens_by_label=matched_by_label,
            entity_penalties_by_label=entity_penalties_by_label,
        )

    def _requests(self, entity_labels: Sequence[str]) -> list[SemanticBucketRequest]:
        requests: list[SemanticBucketRequest] = []
        embedder = self.embedder or HashingTextEmbedder()
        for label in entity_labels:
            query_vector = tuple(embedder.embed(label))
            for bucket_name in entity_bucket_names(label, mode=self.bucket_mode, embedder=embedder):
                token = self.ids.id_for("entity_bucket", bucket_name)
                generated = self.backend.gen(token, beta=1, party_ids=self.party_ids)
                requests.append(
                    SemanticBucketRequest(
                        label=label,
                        bucket_token=token,
                        penalty=self._bucket_penalty(bucket_name),
                        query_vector=query_vector,
                        key_shares=generated,
                    )
                )
        return requests

    def _evaluate(
        self,
        party_id: str,
        request: SemanticBucketRequest,
        universe: Sequence[str],
    ) -> SemanticBucketEvalShares:
        key_share = request.key_shares[party_id]
        eval_many = getattr(self.backend, "eval_many", None)
        if callable(eval_many):
            values = eval_many(key_share, universe)
        else:
            values = [self.backend.eval(key_share, point) for point in universe]
        return SemanticBucketEvalShares(
            party_id=party_id,
            label=request.label,
            bucket_token=request.bucket_token,
            eval_shares=dict(zip(universe, values)),
        )

    def _reconstruct(self, eval_batches: Iterable[SemanticBucketEvalShares]) -> Dict[str, set[str]]:
        grouped: Dict[tuple[str, str], Dict[str, SemanticBucketEvalShares]] = {}
        for batch in eval_batches:
            grouped.setdefault((batch.label, batch.bucket_token), {})[batch.party_id] = batch

        matched_by_label: Dict[str, set[str]] = {}
        for (label, _), by_party in grouped.items():
            missing = set(self.party_ids) - set(by_party)
            if missing:
                raise ValueError(f"Missing semantic entity eval shares for parties: {sorted(missing)}")
            candidate_tokens = set()
            for batch in by_party.values():
                candidate_tokens.update(batch.eval_shares)
            for token in candidate_tokens:
                values = []
                for party_id in self.party_ids:
                    party_values = by_party[party_id].eval_shares
                    if token not in party_values:
                        break
                    values.append(party_values[token])
                else:
                    if sum(values) % self.modulus != 0:
                        matched_by_label.setdefault(label, set()).add(token)
        return matched_by_label

    @staticmethod
    def _entities_for_tokens(
        indexes: Iterable[EntitySemanticIndex],
        tokens: Iterable[str],
        query_vector: Sequence[float],
        fallback_penalty: float,
    ) -> tuple[set[str], Dict[str, float]]:
        token_set = set(tokens)
        entity_ids: set[str] = set()
        entity_penalties: Dict[str, float] = {}
        for index in indexes:
            for token in token_set:
                for entity_id in index.entities_for(token):
                    entity_ids.add(entity_id)
                    candidate_vector = index.vector_for(entity_id)
                    penalty = (
                        fallback_penalty
                        if candidate_vector is None
                        else simgrag_distance(query_vector, candidate_vector)
                    )
                    entity_penalties[entity_id] = min(
                        penalty,
                        entity_penalties.get(entity_id, penalty),
                    )
        return entity_ids, entity_penalties

    @staticmethod
    def _query_vectors(requests: Iterable[SemanticBucketRequest]) -> Dict[str, tuple[float, ...]]:
        query_vectors: Dict[str, tuple[float, ...]] = {}
        for request in requests:
            query_vectors.setdefault(request.label, request.query_vector)
        return query_vectors

    def _bucket_penalty(self, bucket_name: str) -> float:
        if bucket_name.startswith("entity_lsh:"):
            return self.lsh_penalty
        return self.alias_penalty
