from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


# 2^61 - 1 remains the default for backwards-compatible small linear-ORAM
# fixtures. Recursive MP-SPDZ ORAM needs more than 61 bits once its position
# map grows, so scalable configurations explicitly opt in to a field with a
# 124-bit audited packing envelope.  The second prime is NTT-friendly and is
# used only when an HE-backed MP-SPDZ protocol (Hemi/Temi) is selected.  Shares
# are field-specific and must never be reused between the two configurations.
FIELD_PRIME = 2_305_843_009_213_693_951
SCALABLE_FIELD_PRIME = 170_141_183_460_469_231_731_687_303_715_884_105_727
HE_SCALABLE_FIELD_PRIME = (
    170_141_183_460_469_231_731_687_303_715_885_907_969
)
SCALABLE_FIELD_PRIMES = frozenset(
    (SCALABLE_FIELD_PRIME, HE_SCALABLE_FIELD_PRIME)
)
SUPPORTED_FIELD_PRIMES = frozenset((FIELD_PRIME, *SCALABLE_FIELD_PRIMES))
FORMAT_VERSION = 1
EDGE_FIELDS = ("target", "relation", "evidence", "score", "valid")


def reject_scan_only_options(config: "PublicConfig", backend: str) -> None:
    """Fail closed when an experimental backend would ignore scan semantics."""

    unsupported = []
    if config.relation_fanout_per_owner is not None:
        unsupported.append("relation_fanout_per_owner")
    if config.deduplicate_terminal_answers:
        unsupported.append("deduplicate_terminal_answers")
    if unsupported:
        raise ValueError(
            f"{backend} does not implement scan-only option(s): "
            + ", ".join(unsupported)
        )


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
    # Optional public upper bound on the number of edges with the same
    # (source, relation) contributed by one honest owner.  The packed table
    # still reserves ``fanout_per_owner`` records per source, but the scan
    # backend can obliviously compact first-hop relation matches to
    # ``owner_count * relation_fanout_per_owner`` entries before issuing the
    # dependent reads.  ``None`` preserves the original full-frontier circuit.
    relation_fanout_per_owner: int | None = None
    # When enabled, selecting a path suppresses every remaining path with the
    # same secret terminal entity.  The terminal entity stays inside MPC; the
    # existing output contract continues to reveal evidence handles and score.
    deduplicate_terminal_answers: bool = False

    @classmethod
    def load(cls, path: str | Path) -> "PublicConfig":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    @classmethod
    def from_dict(cls, raw: Any) -> "PublicConfig":
        if not isinstance(raw, dict):
            raise ValueError("public configuration must be a JSON object")
        required = {"owners", "entities", "relations", "fanout_per_owner", "top_k"}
        unknown = set(raw) - required - {
            "relation_fanout_per_owner",
            "deduplicate_terminal_answers",
            "score_bits",
            "evidence_bits",
            "field_prime",
        }
        missing = required - set(raw)
        if missing or unknown:
            raise ValueError(f"invalid config keys: missing={sorted(missing)}, unknown={sorted(unknown)}")
        relation_fanout = raw.get("relation_fanout_per_owner")
        if relation_fanout is not None and (
            isinstance(relation_fanout, bool)
            or not isinstance(relation_fanout, int)
        ):
            raise ValueError("relation_fanout_per_owner must be an integer")
        config = cls(
            owners=tuple(raw["owners"]),
            entities={str(k): int(v) for k, v in raw["entities"].items()},
            relations={str(k): int(v) for k, v in raw["relations"].items()},
            fanout_per_owner=int(raw["fanout_per_owner"]),
            top_k=int(raw["top_k"]),
            relation_fanout_per_owner=relation_fanout,
            deduplicate_terminal_answers=raw.get(
                "deduplicate_terminal_answers", False
            ),
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
        if self.relation_fanout_per_owner is not None:
            if (
                isinstance(self.relation_fanout_per_owner, bool)
                or not isinstance(self.relation_fanout_per_owner, int)
            ):
                raise ValueError("relation_fanout_per_owner must be an integer")
            if not 1 <= self.relation_fanout_per_owner <= self.fanout_per_owner:
                raise ValueError(
                    "relation_fanout_per_owner must be in "
                    "[1, fanout_per_owner]"
                )
        if not isinstance(self.deduplicate_terminal_answers, bool):
            raise ValueError("deduplicate_terminal_answers must be a boolean")
        active_candidate_count = (
            self.compacted_candidate_count
            if self.uses_frontier_compaction
            else self.candidate_count
        )
        if self.top_k < 1 or self.top_k > active_candidate_count:
            raise ValueError(f"top_k must be in [1, {active_candidate_count}]")
        if not 1 <= self.score_bits <= 30:
            raise ValueError("score_bits must be in [1, 30]")
        if not 1 <= self.evidence_bits <= 59:
            raise ValueError("evidence_bits must be in [1, 59]")
        if self.field_prime not in SUPPORTED_FIELD_PRIMES:
            raise ValueError("field_prime must be one of the audited primes")

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
    def relation_frontier_per_owner(self) -> int:
        """Public safe first-hop relation bound used by the scan backend."""

        return self.relation_fanout_per_owner or self.fanout_per_owner

    @property
    def frontier_edges(self) -> int:
        """Maximum matching first-hop edges across all owners."""

        return len(self.owners) * self.relation_frontier_per_owner

    @property
    def compacted_candidate_count(self) -> int:
        """Candidates after first-hop compaction and before second filtering."""

        return self.frontier_edges * self.block_edges

    @property
    def uses_frontier_compaction(self) -> bool:
        return self.frontier_edges < self.block_edges

    @property
    def owner_value_count(self) -> int:
        return self.entity_count * self.fanout_per_owner * len(EDGE_FIELDS)

    def public_dict(self) -> dict[str, Any]:
        result = {
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
        # Preserve old configuration digests when the optimization is not
        # explicitly enabled.  Existing prepared shares therefore remain
        # usable with the legacy full-frontier scan.
        if self.relation_fanout_per_owner is not None:
            result["relation_fanout_per_owner"] = self.relation_fanout_per_owner
        if self.deduplicate_terminal_answers:
            result["deduplicate_terminal_answers"] = True
        return result

    @property
    def field_usable_bits(self) -> int:
        # Keep two headroom bits, matching the legacy 61-bit prime / 59-bit
        # compiler configuration. Packed scalable records need up to 124 bits;
        # exact-prime compilation handles non-linear operations without the
        # additional generic masking headroom.
        if self.field_prime in SCALABLE_FIELD_PRIMES:
            # Both scalable fields intentionally expose exactly the same
            # packing/range envelope, so switching preprocessing backends does
            # not alter any encoded record width or circuit comparison width.
            return 124
        return self.field_prime.bit_length() - 2

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json(self.public_dict())).hexdigest()
