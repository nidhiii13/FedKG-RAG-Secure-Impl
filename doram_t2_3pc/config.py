from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


# 2^61 - 1 remains the default for backwards-compatible small linear-ORAM
# fixtures. Recursive MP-SPDZ ORAM needs more than 61 bits once its position
# map grows, so scalable configurations explicitly opt in to 2^127 - 1.
FIELD_PRIME = 2_305_843_009_213_693_951
SCALABLE_FIELD_PRIME = 170_141_183_460_469_231_731_687_303_715_884_105_727
SUPPORTED_FIELD_PRIMES = frozenset((FIELD_PRIME, SCALABLE_FIELD_PRIME))
FORMAT_VERSION = 1
EDGE_FIELDS = ("target", "relation", "evidence", "score", "valid")


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class PublicConfig:
    owners: tuple[str, ...]
    entities: dict[str, int]
    relations: dict[str, int]
    fanout_per_owner: int
    top_k: int
    score_bits: int = 20
    evidence_bits: int = 50
    field_prime: int = FIELD_PRIME

    @classmethod
    def load(cls, path: str | Path) -> "PublicConfig":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        required = {"owners", "entities", "relations", "fanout_per_owner", "top_k"}
        unknown = set(raw) - required - {"score_bits", "evidence_bits", "field_prime"}
        missing = required - set(raw)
        if missing or unknown:
            raise ValueError(f"invalid config keys: missing={sorted(missing)}, unknown={sorted(unknown)}")
        config = cls(
            owners=tuple(raw["owners"]),
            entities={str(k): int(v) for k, v in raw["entities"].items()},
            relations={str(k): int(v) for k, v in raw["relations"].items()},
            fanout_per_owner=int(raw["fanout_per_owner"]),
            top_k=int(raw["top_k"]),
            score_bits=int(raw.get("score_bits", 20)),
            evidence_bits=int(raw.get("evidence_bits", 50)),
            field_prime=int(raw.get("field_prime", FIELD_PRIME)),
        )
        config.validate()
        return config

    def validate(self) -> None:
        if len(self.owners) < 1 or len(set(self.owners)) != len(self.owners):
            raise ValueError("owners must be a non-empty list of unique names")
        if any(not owner for owner in self.owners):
            raise ValueError("owner names must be non-empty")
        entity_slots = sorted(self.entities.values())
        if entity_slots != list(range(1, len(entity_slots) + 1)):
            raise ValueError("entity slots must be unique and contiguous from 1; slot 0 is reserved")
        relation_ids = sorted(self.relations.values())
        if not relation_ids or relation_ids != list(range(1, len(relation_ids) + 1)):
            raise ValueError("relation IDs must be unique and contiguous from 1; ID 0 is reserved")
        if self.fanout_per_owner < 1:
            raise ValueError("fanout_per_owner must be positive")
        if self.top_k < 1 or self.top_k > self.candidate_count:
            raise ValueError(f"top_k must be in [1, {self.candidate_count}]")
        if not 1 <= self.score_bits <= 30:
            raise ValueError("score_bits must be in [1, 30]")
        if not 1 <= self.evidence_bits <= 59:
            raise ValueError("evidence_bits must be in [1, 59]")
        if self.field_prime not in SUPPORTED_FIELD_PRIMES:
            raise ValueError("field_prime must be one of the audited Mersenne primes")

    @property
    def entity_count(self) -> int:
        return len(self.entities) + 1  # includes dummy slot zero

    @property
    def block_edges(self) -> int:
        return len(self.owners) * self.fanout_per_owner

    @property
    def candidate_count(self) -> int:
        return self.block_edges * self.block_edges

    @property
    def owner_value_count(self) -> int:
        return self.entity_count * self.fanout_per_owner * len(EDGE_FIELDS)

    def public_dict(self) -> dict[str, Any]:
        return {
            "version": FORMAT_VERSION,
            "field_prime": self.field_prime,
            "owners": list(self.owners),
            "entities": self.entities,
            "relations": self.relations,
            "fanout_per_owner": self.fanout_per_owner,
            "top_k": self.top_k,
            "score_bits": self.score_bits,
            "evidence_bits": self.evidence_bits,
        }

    @property
    def field_usable_bits(self) -> int:
        # Keep two headroom bits, matching the legacy 61-bit prime / 59-bit
        # compiler configuration. Packed scalable records need up to 124 bits;
        # exact-prime compilation handles non-linear operations without the
        # additional generic masking headroom.
        headroom = 3 if self.field_prime == SCALABLE_FIELD_PRIME else 2
        return self.field_prime.bit_length() - headroom

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json(self.public_dict())).hexdigest()
