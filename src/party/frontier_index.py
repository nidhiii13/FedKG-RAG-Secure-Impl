"""Party-local opaque frontier index for cross-party path handoff."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable

from src.crypto.hmac_ids import HmacIdProvider
from src.party.secure_index import SecurePartyIndex


@dataclass(frozen=True)
class FrontierIndex:
    token_to_entities: Dict[str, list[str]]

    @classmethod
    def from_secure_index(cls, index: SecurePartyIndex, ids: HmacIdProvider) -> "FrontierIndex":
        token_to_entities: Dict[str, list[str]] = {}
        for entity_id, display in index.display_entities.items():
            token = frontier_token(ids, display)
            token_to_entities.setdefault(token, []).append(entity_id)
        return cls({token: sorted(set(values)) for token, values in token_to_entities.items()})

    @property
    def tokens(self) -> list[str]:
        return sorted(self.token_to_entities)

    def entities_for(self, token: str) -> list[str]:
        return list(self.token_to_entities.get(token, []))


def frontier_token(ids: HmacIdProvider, entity_label: object) -> str:
    return ids.id_for("frontier_entity", entity_label)
