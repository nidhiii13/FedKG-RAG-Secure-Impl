"""Plaintext-free encoded index snapshots for replicated FSS evaluators."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from src.crypto.hmac_ids import HmacIdProvider
from src.party.frontier_index import FrontierIndex
from src.party.secure_index import SecurePartyIndex

SNAPSHOT_VERSION = "fedkg-opaque-index-v1"
FORBIDDEN_FIELDS = frozenset(
    {
        "party_id",
        "display_entities",
        "display_relations",
        "alignment_index",
        "setup_key",
        "hmac_key",
    }
)


@dataclass(frozen=True)
class OpaqueIndexSnapshot:
    partition_id: str
    adjacency: dict[str, dict[str, list[str]]]
    reverse_adjacency: dict[str, dict[str, list[str]]]
    type_index: dict[str, list[str]]
    frontier_index: dict[str, list[str]]
    entity_points: list[str]
    relation_points: list[str]
    version: str = SNAPSHOT_VERSION

    @classmethod
    def from_secure_index(
        cls,
        index: SecurePartyIndex,
        ids: HmacIdProvider,
    ) -> "OpaqueIndexSnapshot":
        frontier = FrontierIndex.from_secure_index(index, ids)
        return cls(
            partition_id=ids.id_for("index_partition", index.party_id),
            adjacency=_canonical_nested(index.adjacency),
            reverse_adjacency=_canonical_nested(index.reverse_adjacency),
            type_index={key: sorted(set(values)) for key, values in sorted(index.type_index.items())},
            frontier_index={
                key: sorted(set(values)) for key, values in sorted(frontier.token_to_entities.items())
            },
            entity_points=sorted(index.display_entities),
            relation_points=sorted(index.local_relations),
        )

    @classmethod
    def from_json(cls, path: str | Path) -> "OpaqueIndexSnapshot":
        payload = json.loads(Path(path).read_text())
        if not isinstance(payload, dict):
            raise ValueError("opaque index snapshot must be a JSON object")
        _reject_forbidden_fields(payload)
        expected = {
            "version",
            "partition_id",
            "adjacency",
            "reverse_adjacency",
            "type_index",
            "frontier_index",
            "entity_points",
            "relation_points",
        }
        if set(payload) != expected:
            raise ValueError(f"unexpected snapshot fields: {sorted(set(payload) ^ expected)}")
        if payload["version"] != SNAPSHOT_VERSION:
            raise ValueError(f"unsupported snapshot version: {payload['version']}")
        snapshot = cls(**payload)
        snapshot.validate()
        return snapshot

    def validate(self) -> None:
        if self.version != SNAPSHOT_VERSION:
            raise ValueError(f"unsupported snapshot version: {self.version}")
        if not _is_hex_identifier(self.partition_id):
            raise ValueError("partition_id must be an opaque hexadecimal identifier")
        for name, values in (
            ("entity_points", self.entity_points),
            ("relation_points", self.relation_points),
        ):
            if values != sorted(set(values)) or not all(_is_hex_identifier(value) for value in values):
                raise ValueError(f"{name} must contain sorted unique opaque identifiers")
        entity_set = set(self.entity_points)
        relation_set = set(self.relation_points)
        for adjacency in (self.adjacency, self.reverse_adjacency):
            for entity_id, relations in adjacency.items():
                if entity_id not in entity_set or not isinstance(relations, dict):
                    raise ValueError("adjacency references an unknown entity")
                for relation_id, targets in relations.items():
                    if relation_id not in relation_set:
                        raise ValueError("adjacency references an unknown relation")
                    if any(target not in entity_set for target in targets):
                        raise ValueError("adjacency references an unknown target entity")
        for members in self.type_index.values():
            if any(member not in entity_set for member in members):
                raise ValueError("type index references an unknown entity")
        for members in self.frontier_index.values():
            if any(member not in entity_set for member in members):
                raise ValueError("frontier index references an unknown entity")

    def as_dict(self) -> dict[str, object]:
        payload = {
            "version": self.version,
            "partition_id": self.partition_id,
            "adjacency": self.adjacency,
            "reverse_adjacency": self.reverse_adjacency,
            "type_index": self.type_index,
            "frontier_index": self.frontier_index,
            "entity_points": self.entity_points,
            "relation_points": self.relation_points,
        }
        _reject_forbidden_fields(payload)
        return payload

    def canonical_json(self) -> str:
        self.validate()
        return json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    def digest(self) -> str:
        return hashlib.sha256(self.canonical_json().encode("ascii")).hexdigest()

    def write(self, path: str | Path) -> None:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(self.as_dict(), indent=2, sort_keys=True))


@dataclass(frozen=True)
class ReplicatedEvaluatorIndex:
    snapshots: tuple[OpaqueIndexSnapshot, ...]

    @property
    def entity_points(self) -> list[str]:
        return sorted({point for snapshot in self.snapshots for point in snapshot.entity_points})

    @property
    def relation_points(self) -> list[str]:
        return sorted({point for snapshot in self.snapshots for point in snapshot.relation_points})

    @property
    def frontier_points(self) -> list[str]:
        return sorted({point for snapshot in self.snapshots for point in snapshot.frontier_index})

    def entity_partitions(self, entity_id: str) -> list[str]:
        return sorted(
            snapshot.partition_id for snapshot in self.snapshots if entity_id in snapshot.entity_points
        )

    def relation_partitions(self, relation_id: str) -> list[str]:
        return sorted(
            snapshot.partition_id for snapshot in self.snapshots if relation_id in snapshot.relation_points
        )


def _canonical_nested(
    values: Mapping[str, Mapping[str, list[str]]],
) -> dict[str, dict[str, list[str]]]:
    return {
        outer: {
            inner: sorted(set(items))
            for inner, items in sorted(inner_values.items())
        }
        for outer, inner_values in sorted(values.items())
    }


def _is_hex_identifier(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) >= 16
        and len(value) % 2 == 0
        and all(character in "0123456789abcdef" for character in value)
    )


def _reject_forbidden_fields(value: object) -> None:
    if isinstance(value, dict):
        forbidden = FORBIDDEN_FIELDS.intersection(value)
        if forbidden:
            raise ValueError(f"plaintext-sensitive snapshot fields are forbidden: {sorted(forbidden)}")
        for nested in value.values():
            _reject_forbidden_fields(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_forbidden_fields(nested)

