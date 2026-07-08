"""Deterministic semantic buckets for private entity routing."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict

from src.common.normalization import normalize_text
from src.crypto.hmac_ids import HmacIdProvider
from src.party.secure_index import SecurePartyIndex
from src.semantic.lsh import HashingTextEmbedder, SimHashLsh, TextEmbedder
from src.semantic.relation_buckets import SemanticBucketMode

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_STOPWORDS = {"a", "an", "the"}


def entity_alias_bucket_names(label: object) -> list[str]:
    text = normalize_text(str(label).replace("_", " "))
    tokens = [token for token in _TOKEN_RE.findall(text) if token not in _STOPWORDS]
    buckets = {f"entity_tok:{token}" for token in tokens}
    for left, right in zip(tokens, tokens[1:]):
        buckets.add(f"entity_bigram:{left}:{right}")
    return sorted(buckets)


def entity_lsh_bucket_names(
    label: object,
    embedder: TextEmbedder | None = None,
    lsh: SimHashLsh | None = None,
) -> list[str]:
    embedder = embedder or HashingTextEmbedder()
    lsh = lsh or SimHashLsh()
    return [f"entity_{bucket}" for bucket in lsh.bucket_names(embedder.embed(label))]


def entity_bucket_names(
    label: object,
    mode: SemanticBucketMode = "hybrid",
    embedder: TextEmbedder | None = None,
    lsh: SimHashLsh | None = None,
) -> list[str]:
    if mode == "alias":
        return entity_alias_bucket_names(label)
    if mode == "lsh":
        return entity_lsh_bucket_names(label, embedder=embedder, lsh=lsh)
    if mode == "hybrid":
        return sorted(
            set(entity_alias_bucket_names(label))
            | set(entity_lsh_bucket_names(label, embedder=embedder, lsh=lsh))
        )
    raise ValueError(f"Unsupported semantic bucket mode: {mode}")


def entity_bucket_tokens(
    ids: HmacIdProvider,
    label: object,
    mode: SemanticBucketMode = "hybrid",
    embedder: TextEmbedder | None = None,
    lsh: SimHashLsh | None = None,
) -> list[str]:
    return [
        ids.id_for("entity_bucket", bucket)
        for bucket in entity_bucket_names(label, mode=mode, embedder=embedder, lsh=lsh)
    ]


@dataclass(frozen=True)
class EntitySemanticIndex:
    bucket_to_entities: Dict[str, list[str]]

    @classmethod
    def from_secure_index(
        cls,
        index: SecurePartyIndex,
        ids: HmacIdProvider,
        mode: SemanticBucketMode = "hybrid",
        embedder: TextEmbedder | None = None,
        lsh: SimHashLsh | None = None,
    ) -> "EntitySemanticIndex":
        bucket_to_entities: Dict[str, list[str]] = {}
        for entity_id, display in index.display_entities.items():
            for token in entity_bucket_tokens(ids, display, mode=mode, embedder=embedder, lsh=lsh):
                bucket_to_entities.setdefault(token, []).append(entity_id)
        return cls({token: sorted(set(values)) for token, values in bucket_to_entities.items()})

    @property
    def tokens(self) -> list[str]:
        return sorted(self.bucket_to_entities)

    def entities_for(self, token: str) -> list[str]:
        return list(self.bucket_to_entities.get(token, []))
