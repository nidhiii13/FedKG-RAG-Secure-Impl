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
    query_vector: tuple[float, ...]
    key_shares: Mapping[str, DpfKeyShare]


@dataclass(frozen=True)
class SemanticBucketEvalShares:
    party_id: str
    label: str
    eval_shares: Dict[str, int]


@dataclass(frozen=True)
class SemanticRelationRouting:
    relation_ids_by_label: Dict[str, set[str]]
    relation_penalties_by_label: Dict[str, Dict[str, float]]


@dataclass(frozen=True)
class SemanticEntityRouting:
    entity_ids_by_label: Dict[str, set[str]]
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
        token_to_relations = self._global_token_to_relations(indexes.values())
        requests = self._requests(relation_labels)
        eval_batches = [
            self._evaluate(party_id, request, universe)
            for request in requests
            for party_id in self.party_ids
        ]
        query_vectors = self._query_vectors(requests)
        relation_ids_by_label: Dict[str, set[str]] = {}
        relation_penalties_by_label: Dict[str, Dict[str, float]] = {}
        relation_share_totals = self._relation_share_totals(eval_batches, token_to_relations)
        for label, relation_totals in relation_share_totals.items():
            relation_ids = {
                relation_id
                for relation_id, value in relation_totals.items()
                if value % self.modulus != 0
            }
            if not relation_ids:
                continue
            relation_ids_by_label[label] = relation_ids
            relation_penalties_by_label[label] = self._penalties_for_relations(
                indexes.values(),
                relation_ids,
                query_vectors[label],
                self.lsh_penalty,
            )
        return SemanticRelationRouting(
            relation_ids_by_label=relation_ids_by_label,
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
            eval_shares=dict(zip(universe, values)),
        )

    @staticmethod
    def _global_token_to_relations(
        indexes: Iterable[RelationSemanticIndex],
    ) -> Dict[str, set[str]]:
        token_to_relations: Dict[str, set[str]] = {}
        for index in indexes:
            for token in index.tokens:
                token_to_relations.setdefault(token, set()).update(index.relations_for(token))
        return token_to_relations

    def _relation_share_totals(
        self,
        eval_batches: Iterable[SemanticBucketEvalShares],
        token_to_relations: Mapping[str, set[str]],
    ) -> Dict[str, Dict[str, int]]:
        """Project DPF eval shares directly into relation-output shares.

        This avoids returning matched bucket tokens from the routing step. Each
        party contributes its DPF output share to every relation output slot
        associated with that bucket token in the shared semantic-output universe.
        Non-matching buckets cancel when all party shares are summed; matching
        buckets reconstruct to beta and therefore leave a nonzero candidate
        relation total.
        """

        totals: Dict[str, Dict[str, int]] = {}
        for batch in eval_batches:
            label_totals = totals.setdefault(batch.label, {})
            for token, value in batch.eval_shares.items():
                for relation_id in token_to_relations.get(token, set()):
                    label_totals[relation_id] = (
                        label_totals.get(relation_id, 0) + value
                    ) % self.modulus
        return totals

    @staticmethod
    def _penalties_for_relations(
        indexes: Iterable[RelationSemanticIndex],
        relation_ids: Iterable[str],
        query_vector: Sequence[float],
        fallback_penalty: float,
    ) -> Dict[str, float]:
        wanted = set(relation_ids)
        penalties: Dict[str, float] = {}
        for index in indexes:
            for relation_id in wanted:
                candidate_vector = index.vector_for(relation_id)
                if candidate_vector is None:
                    continue
                penalty = simgrag_distance(query_vector, candidate_vector)
                penalties[relation_id] = min(
                    penalty,
                    penalties.get(relation_id, penalty),
                )
        for relation_id in wanted:
            penalties.setdefault(relation_id, fallback_penalty)
        return penalties

    @staticmethod
    def _query_vectors(requests: Iterable[SemanticBucketRequest]) -> Dict[str, tuple[float, ...]]:
        query_vectors: Dict[str, tuple[float, ...]] = {}
        for request in requests:
            query_vectors.setdefault(request.label, request.query_vector)
        return query_vectors

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
        token_to_entities = self._global_token_to_entities(indexes.values())
        requests = self._requests(entity_labels)
        eval_batches = [
            self._evaluate(party_id, request, universe)
            for request in requests
            for party_id in self.party_ids
        ]
        query_vectors = self._query_vectors(requests)
        entity_ids_by_label: Dict[str, set[str]] = {}
        entity_penalties_by_label: Dict[str, Dict[str, float]] = {}
        entity_share_totals = self._entity_share_totals(eval_batches, token_to_entities)
        for label, entity_totals in entity_share_totals.items():
            entity_ids = {
                entity_id
                for entity_id, value in entity_totals.items()
                if value % self.modulus != 0
            }
            if not entity_ids:
                continue
            entity_ids_by_label[label] = entity_ids
            entity_penalties_by_label[label] = self._penalties_for_entities(
                indexes.values(),
                entity_ids,
                query_vectors[label],
                self.lsh_penalty,
            )
        return SemanticEntityRouting(
            entity_ids_by_label=entity_ids_by_label,
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
            eval_shares=dict(zip(universe, values)),
        )

    @staticmethod
    def _global_token_to_entities(
        indexes: Iterable[EntitySemanticIndex],
    ) -> Dict[str, set[str]]:
        token_to_entities: Dict[str, set[str]] = {}
        for index in indexes:
            for token in index.tokens:
                token_to_entities.setdefault(token, set()).update(index.entities_for(token))
        return token_to_entities

    def _entity_share_totals(
        self,
        eval_batches: Iterable[SemanticBucketEvalShares],
        token_to_entities: Mapping[str, set[str]],
    ) -> Dict[str, Dict[str, int]]:
        totals: Dict[str, Dict[str, int]] = {}
        for batch in eval_batches:
            label_totals = totals.setdefault(batch.label, {})
            for token, value in batch.eval_shares.items():
                for entity_id in token_to_entities.get(token, set()):
                    label_totals[entity_id] = (
                        label_totals.get(entity_id, 0) + value
                    ) % self.modulus
        return totals

    @staticmethod
    def _penalties_for_entities(
        indexes: Iterable[EntitySemanticIndex],
        entity_ids: Iterable[str],
        query_vector: Sequence[float],
        fallback_penalty: float,
    ) -> Dict[str, float]:
        wanted = set(entity_ids)
        penalties: Dict[str, float] = {}
        for index in indexes:
            for entity_id in wanted:
                candidate_vector = index.vector_for(entity_id)
                if candidate_vector is None:
                    continue
                penalty = simgrag_distance(query_vector, candidate_vector)
                penalties[entity_id] = min(
                    penalty,
                    penalties.get(entity_id, penalty),
                )
        for entity_id in wanted:
            penalties.setdefault(entity_id, fallback_penalty)
        return penalties

    @staticmethod
    def _query_vectors(requests: Iterable[SemanticBucketRequest]) -> Dict[str, tuple[float, ...]]:
        query_vectors: Dict[str, tuple[float, ...]] = {}
        for request in requests:
            query_vectors.setdefault(request.label, request.query_vector)
        return query_vectors
