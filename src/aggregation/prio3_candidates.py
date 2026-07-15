"""Padded candidate-vector construction for the optional Prio3 backend."""

from __future__ import annotations

import hashlib
import hmac
import math
from dataclasses import dataclass
from typing import Mapping, Protocol, Sequence

from src.aggregation.prio3_types import Prio3SumVecRequest, Prio3SumVecResult


class Prio3SumVecBackend(Protocol):
    def sum_vec(self, request: Prio3SumVecRequest) -> Prio3SumVecResult:
        ...


@dataclass(frozen=True)
class CandidateContribution:
    """One data party's local contribution for an opaque candidate path."""

    party_id: str
    candidate_id: str
    score: float
    support: int


@dataclass(frozen=True)
class CandidateVectorConfig:
    aggregator_count: int
    capacity: int
    score_scale: int = 1_000_000
    score_bits: int = 32
    support_bits: int = 16
    context_prefix: str = "fedkg-rag/prio3/candidates/v1"

    def validate(self) -> None:
        if not 2 <= self.aggregator_count <= 255:
            raise ValueError("aggregator_count must be in the range [2, 255]")
        if self.capacity < 1:
            raise ValueError("capacity must be positive")
        if self.score_scale < 1:
            raise ValueError("score_scale must be positive")
        if not 1 <= self.score_bits < 64:
            raise ValueError("score_bits must be in the range [1, 63]")
        if not 1 <= self.support_bits < 64:
            raise ValueError("support_bits must be in the range [1, 63]")


@dataclass(frozen=True)
class CandidateSlot:
    handle: str
    candidate_id: str | None

    @property
    def is_padding(self) -> bool:
        return self.candidate_id is None


@dataclass(frozen=True)
class PartyCandidateVectors:
    party_id: str
    presence: list[int]
    score: list[int]
    support: list[int]


@dataclass(frozen=True)
class CandidateAggregate:
    candidate_id: str
    handle: str
    presence_count: int
    score_sum: int
    support_sum: int
    score_scale: int

    @property
    def average_score(self) -> float:
        if self.presence_count == 0:
            raise ValueError("cannot average a candidate with zero presence")
        return self.score_sum / self.presence_count / self.score_scale


@dataclass(frozen=True)
class PrioCandidateAggregationResult:
    candidates: list[CandidateAggregate]
    slots: list[CandidateSlot]
    party_count: int
    aggregator_count: int


@dataclass(frozen=True)
class SessionCandidateHandleProvider:
    """Derive unlinkable per-query handles from existing opaque candidate IDs."""

    key: bytes
    query_nonce: bytes

    def __post_init__(self) -> None:
        if len(self.key) < 16:
            raise ValueError("candidate handle key must contain at least 16 bytes")
        if len(self.query_nonce) < 16:
            raise ValueError("query_nonce must contain at least 16 bytes")

    def candidate_handle(self, candidate_id: str) -> str:
        return self._derive(b"candidate\x00" + candidate_id.encode("utf-8"))

    def padding_handle(self, index: int) -> str:
        return self._derive(b"padding\x00" + index.to_bytes(8, "big"))

    def _derive(self, message: bytes) -> str:
        return hmac.new(
            self.key,
            b"fedkg-rag/prio3/handle/v1\x00" + self.query_nonce + b"\x00" + message,
            hashlib.sha256,
        ).hexdigest()


class PrioCandidateAggregator:
    """Build and locally reconstruct padded Prio3 candidate aggregates.

    This class is the local validation boundary. A production implementation
    must retain the three aggregate-share vectors instead of reconstructing them
    through ``Prio3SumVecBackend.sum_vec``.
    """

    def __init__(
        self,
        backend: Prio3SumVecBackend,
        config: CandidateVectorConfig,
        handles: SessionCandidateHandleProvider,
    ) -> None:
        config.validate()
        self.backend = backend
        self.config = config
        self.handles = handles

    def aggregate(
        self,
        party_ids: Sequence[str],
        contributions: Sequence[CandidateContribution],
    ) -> PrioCandidateAggregationResult:
        parties = list(dict.fromkeys(party_ids))
        if len(parties) != len(party_ids):
            raise ValueError("party_ids must be unique")
        if not parties:
            raise ValueError("at least one data party is required")
        contribution_map = self._validate_contributions(parties, contributions)
        slots = self._build_slots(contributions)
        vectors = self._build_party_vectors(parties, contribution_map, slots)

        presence = self._sum_vec("presence", [row.presence for row in vectors], bits=1)
        scores = self._sum_vec("score", [row.score for row in vectors], bits=self.config.score_bits)
        support = self._sum_vec(
            "support",
            [row.support for row in vectors],
            bits=self.config.support_bits,
        )

        candidates = []
        for index, slot in enumerate(slots):
            if slot.candidate_id is None:
                continue
            candidates.append(
                CandidateAggregate(
                    candidate_id=slot.candidate_id,
                    handle=slot.handle,
                    presence_count=presence[index],
                    score_sum=scores[index],
                    support_sum=support[index],
                    score_scale=self.config.score_scale,
                )
            )
        return PrioCandidateAggregationResult(
            candidates=candidates,
            slots=slots,
            party_count=len(parties),
            aggregator_count=self.config.aggregator_count,
        )

    def _validate_contributions(
        self,
        party_ids: Sequence[str],
        contributions: Sequence[CandidateContribution],
    ) -> Mapping[tuple[str, str], CandidateContribution]:
        allowed_parties = set(party_ids)
        result: dict[tuple[str, str], CandidateContribution] = {}
        maximum_score = 1 << self.config.score_bits
        maximum_support = 1 << self.config.support_bits
        for contribution in contributions:
            if contribution.party_id not in allowed_parties:
                raise ValueError(f"unknown contribution party: {contribution.party_id}")
            if not contribution.candidate_id:
                raise ValueError("candidate_id must not be empty")
            if not math.isfinite(contribution.score) or contribution.score < 0:
                raise ValueError("candidate score must be finite and non-negative")
            encoded_score = int(round(contribution.score * self.config.score_scale))
            if encoded_score >= maximum_score:
                raise ValueError("encoded candidate score exceeds score_bits")
            if contribution.support < 0 or contribution.support >= maximum_support:
                raise ValueError("candidate support exceeds support_bits")
            key = (contribution.party_id, contribution.candidate_id)
            if key in result:
                raise ValueError("a party may contribute to a candidate only once")
            result[key] = contribution
        return result

    def _build_slots(self, contributions: Sequence[CandidateContribution]) -> list[CandidateSlot]:
        candidate_ids = sorted({contribution.candidate_id for contribution in contributions})
        if len(candidate_ids) > self.config.capacity:
            raise ValueError(
                f"candidate count {len(candidate_ids)} exceeds padded capacity {self.config.capacity}"
            )
        slots = [
            CandidateSlot(self.handles.candidate_handle(candidate_id), candidate_id)
            for candidate_id in candidate_ids
        ]
        slots.extend(
            CandidateSlot(self.handles.padding_handle(index), None)
            for index in range(self.config.capacity - len(slots))
        )
        return sorted(slots, key=lambda slot: slot.handle)

    def _build_party_vectors(
        self,
        party_ids: Sequence[str],
        contributions: Mapping[tuple[str, str], CandidateContribution],
        slots: Sequence[CandidateSlot],
    ) -> list[PartyCandidateVectors]:
        rows = []
        for party_id in party_ids:
            presence = []
            scores = []
            support = []
            for slot in slots:
                item = contributions.get((party_id, slot.candidate_id)) if slot.candidate_id else None
                presence.append(int(item is not None))
                scores.append(
                    int(round(item.score * self.config.score_scale)) if item is not None else 0
                )
                support.append(item.support if item is not None else 0)
            rows.append(PartyCandidateVectors(party_id, presence, scores, support))
        return rows

    def _sum_vec(self, name: str, measurements: Sequence[Sequence[int]], bits: int) -> list[int]:
        result = self.backend.sum_vec(
            Prio3SumVecRequest(
                measurements=measurements,
                aggregator_count=self.config.aggregator_count,
                bits=bits,
                context=f"{self.config.context_prefix}/{name}",
            )
        )
        return result.aggregate
