"""Deterministic semantic buckets for private relation routing."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterable, Literal

from src.common.normalization import normalize_text
from src.crypto.hmac_ids import HmacIdProvider
from src.party.secure_index import SecurePartyIndex
from src.semantic.lsh import HashingTextEmbedder, SimHashLsh, TextEmbedder

_TOKEN_RE = re.compile(r"[a-z0-9]+")
SemanticBucketMode = Literal["alias", "lsh", "hybrid"]

_ALIASES = {
    "actor": {"actor", "actors", "acted", "acting", "star", "stars", "starred", "cast"},
    "director": {"direct", "directed", "director", "directors"},
    "writer": {"write", "writes", "written", "writer", "writers", "screenwriter"},
    "genre": {"genre", "genres", "type", "types"},
    "language": {"language", "languages"},
    "release": {"release", "released", "year", "date"},
    "tag": {"tag", "tags"},
}

_TOKEN_TO_ALIAS = {
    token: alias
    for alias, tokens in _ALIASES.items()
    for token in tokens
}


def relation_alias_bucket_names(label: object) -> list[str]:
    text = normalize_text(str(label).replace("_", " "))
    tokens = _TOKEN_RE.findall(text)
    buckets = {f"tok:{token}" for token in tokens}
    buckets.update(f"alias:{_TOKEN_TO_ALIAS[token]}" for token in tokens if token in _TOKEN_TO_ALIAS)
    for left, right in zip(tokens, tokens[1:]):
        buckets.add(f"bigram:{left}:{right}")
    return sorted(buckets)


def relation_lsh_bucket_names(
    label: object,
    embedder: TextEmbedder | None = None,
    lsh: SimHashLsh | None = None,
) -> list[str]:
    embedder = embedder or HashingTextEmbedder()
    lsh = lsh or SimHashLsh()
    return lsh.bucket_names(embedder.embed(label))


def relation_bucket_names(
    label: object,
    mode: SemanticBucketMode = "hybrid",
    embedder: TextEmbedder | None = None,
    lsh: SimHashLsh | None = None,
) -> list[str]:
    if mode == "alias":
        return relation_alias_bucket_names(label)
    if mode == "lsh":
        return relation_lsh_bucket_names(label, embedder=embedder, lsh=lsh)
    if mode == "hybrid":
        return sorted(
            set(relation_alias_bucket_names(label))
            | set(relation_lsh_bucket_names(label, embedder=embedder, lsh=lsh))
        )
    raise ValueError(f"Unsupported semantic bucket mode: {mode}")


def relation_bucket_tokens(
    ids: HmacIdProvider,
    label: object,
    mode: SemanticBucketMode = "hybrid",
    embedder: TextEmbedder | None = None,
    lsh: SimHashLsh | None = None,
) -> list[str]:
    return [
        ids.relation_bucket_id(bucket)
        for bucket in relation_bucket_names(label, mode=mode, embedder=embedder, lsh=lsh)
    ]


@dataclass(frozen=True)
class RelationSemanticIndex:
    bucket_to_relations: Dict[str, list[str]]
    relation_vectors: Dict[str, tuple[float, ...]]

    @classmethod
    def from_secure_index(
        cls,
        index: SecurePartyIndex,
        ids: HmacIdProvider,
        mode: SemanticBucketMode = "hybrid",
        embedder: TextEmbedder | None = None,
        lsh: SimHashLsh | None = None,
    ) -> "RelationSemanticIndex":
        bucket_to_relations: Dict[str, list[str]] = {}
        relation_vectors: Dict[str, tuple[float, ...]] = {}
        embedder = embedder or HashingTextEmbedder()
        relation_items = list(index.display_relations.items())
        embed_many = getattr(embedder, "embed_many", None)
        if callable(embed_many):
            vectors = embed_many([display for _, display in relation_items])
        else:
            vectors = [embedder.embed(display) for _, display in relation_items]
        for (relation_id, display), vector in zip(relation_items, vectors):
            relation_vectors[relation_id] = tuple(vector)
            for token in relation_bucket_tokens(ids, display, mode=mode, embedder=embedder, lsh=lsh):
                bucket_to_relations.setdefault(token, []).append(relation_id)
        return cls(
            {token: sorted(set(values)) for token, values in bucket_to_relations.items()},
            relation_vectors,
        )

    @property
    def tokens(self) -> list[str]:
        return sorted(self.bucket_to_relations)

    def relations_for(self, token: str) -> list[str]:
        return list(self.bucket_to_relations.get(token, []))

    def vector_for(self, relation_id: str) -> tuple[float, ...] | None:
        return self.relation_vectors.get(relation_id)


def relation_ids_for_bucket_matches(
    indexes: Iterable[RelationSemanticIndex],
    matched_tokens: Iterable[str],
) -> set[str]:
    matched = set(matched_tokens)
    out: set[str] = set()
    for index in indexes:
        for token in matched:
            out.update(index.relations_for(token))
    return out
