"""Semantic routing through role-separated projected FSS evaluator services."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from src.crypto.hmac_ids import HmacIdProvider
from src.orchestration.private_semantic_routing import (
    SemanticEntityRouting,
    SemanticRelationRouting,
)
from src.orchestration.role_separated_fss_query import RoleSeparatedFssQueryOrchestrator
from src.semantic.entity_buckets import entity_bucket_names
from src.semantic.lsh import HashingTextEmbedder, TextEmbedder
from src.semantic.relation_buckets import SemanticBucketMode, relation_bucket_names


@dataclass(frozen=True)
class RoleSeparatedSemanticRouter:
    ids: HmacIdProvider
    lookup: RoleSeparatedFssQueryOrchestrator
    bucket_mode: SemanticBucketMode = "hybrid"
    embedder: TextEmbedder | None = None

    def __post_init__(self) -> None:
        snapshot_mode = self.lookup.projection_builder.index.semantic_bucket_mode
        if snapshot_mode is None:
            raise ValueError("evaluator snapshots do not contain semantic bucket indexes")
        if snapshot_mode != self.bucket_mode:
            raise ValueError(
                f"semantic bucket mode mismatch: snapshots={snapshot_mode}, query={self.bucket_mode}"
            )

    def route_relations(
        self,
        labels: Sequence[str],
        capacity: int,
    ) -> SemanticRelationRouting:
        candidates, penalties = self._route(
            labels,
            domain="relation_bucket",
            capacity=capacity,
        )
        return SemanticRelationRouting(candidates, penalties)

    def route_entities(
        self,
        labels: Sequence[str],
        capacity: int,
    ) -> SemanticEntityRouting:
        candidates, penalties = self._route(
            labels,
            domain="entity_bucket",
            capacity=capacity,
        )
        return SemanticEntityRouting(candidates, penalties)

    def _route(
        self,
        labels: Sequence[str],
        domain: str,
        capacity: int,
    ) -> tuple[dict[str, set[str]], dict[str, dict[str, float]]]:
        embedder = self.embedder or HashingTextEmbedder()
        ids_by_label: dict[str, set[str]] = {}
        penalties_by_label: dict[str, dict[str, float]] = {}
        for label in dict.fromkeys(labels):
            if domain == "relation_bucket":
                names = relation_bucket_names(
                    label,
                    mode=self.bucket_mode,
                    embedder=embedder,
                )
                encode = self.ids.relation_bucket_id
            elif domain == "entity_bucket":
                names = entity_bucket_names(
                    label,
                    mode=self.bucket_mode,
                    embedder=embedder,
                )
                encode = lambda value: self.ids.id_for("entity_bucket", value)
            else:
                raise ValueError(f"unsupported semantic routing domain: {domain}")

            match_counts: dict[str, int] = {}
            for bucket_name in names:
                request_id = self.ids.id_for(
                    "role_semantic_request",
                    f"{domain}:{label}:{bucket_name}",
                )
                result = self.lookup.query(
                    request_id,
                    domain,  # type: ignore[arg-type]
                    encode(bucket_name),
                    capacity,
                )
                for candidate_id, value in result.candidate_values.items():
                    if value:
                        match_counts[candidate_id] = match_counts.get(candidate_id, 0) + 1

            if not match_counts:
                continue
            denominator = max(len(names), 1)
            ids_by_label[label] = set(match_counts)
            penalties_by_label[label] = {
                candidate_id: 1.0 - min(count, denominator) / denominator
                for candidate_id, count in match_counts.items()
            }
        return ids_by_label, penalties_by_label

