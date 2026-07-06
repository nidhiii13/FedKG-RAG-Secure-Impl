"""Private semantic bucket routing for relation candidates."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, Mapping, Sequence

from src.crypto.dpf import DpfBackend, DpfKeyShare
from src.crypto.dpf_domain import DPF_MODULUS
from src.crypto.hmac_ids import HmacIdProvider
from src.semantic.relation_buckets import RelationSemanticIndex, relation_bucket_tokens


@dataclass(frozen=True)
class SemanticBucketRequest:
    label: str
    bucket_token: str
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


@dataclass(frozen=True)
class PrivateSemanticRelationRouter:
    ids: HmacIdProvider
    backend: DpfBackend
    party_ids: Sequence[str]
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
        relation_ids_by_label = {
            label: self._relations_for_tokens(indexes.values(), tokens)
            for label, tokens in matched_by_label.items()
        }
        return SemanticRelationRouting(
            relation_ids_by_label=relation_ids_by_label,
            matched_bucket_tokens_by_label=matched_by_label,
        )

    def _requests(self, relation_labels: Sequence[str]) -> list[SemanticBucketRequest]:
        requests: list[SemanticBucketRequest] = []
        for label in relation_labels:
            for token in relation_bucket_tokens(self.ids, label):
                generated = self.backend.gen(token, beta=1, party_ids=self.party_ids)
                requests.append(SemanticBucketRequest(label=label, bucket_token=token, key_shares=generated))
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
    ) -> set[str]:
        token_set = set(tokens)
        relation_ids: set[str] = set()
        for index in indexes:
            for token in token_set:
                relation_ids.update(index.relations_for(token))
        return relation_ids
