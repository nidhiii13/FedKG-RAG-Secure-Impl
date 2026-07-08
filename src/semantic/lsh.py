"""Local embedding and LSH bucket helpers for semantic routing."""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass
from typing import Protocol, Sequence

from src.common.normalization import normalize_text

_TOKEN_RE = re.compile(r"[a-z0-9]+")


class TextEmbedder(Protocol):
    def embed(self, text: object) -> list[float]:
        ...


@dataclass(frozen=True)
class HashingTextEmbedder:
    """Deterministic local text embedder used until an external model is wired.

    It creates a normalized signed hashing vector from word tokens and character
    trigrams. This is not a neural embedding model, but it exercises the same LSH
    bucket interface that a Nomic/Ollama embedder can later implement.
    """

    dimensions: int = 128

    def embed(self, text: object) -> list[float]:
        features = self._features(text)
        vector = [0.0] * self.dimensions
        for feature in features:
            digest = hashlib.sha256(feature.encode("utf-8")).digest()
            index = int.from_bytes(digest[:4], "big") % self.dimensions
            sign = 1.0 if digest[4] & 1 else -1.0
            vector[index] += sign
        norm = math.sqrt(sum(value * value for value in vector))
        if norm == 0.0:
            return vector
        return [value / norm for value in vector]

    @staticmethod
    def _features(text: object) -> list[str]:
        normalized = normalize_text(str(text).replace("_", " "))
        tokens = _TOKEN_RE.findall(normalized)
        features = [f"tok:{token}" for token in tokens]
        compact = "".join(tokens)
        features.extend(f"tri:{compact[index:index + 3]}" for index in range(max(0, len(compact) - 2)))
        return features or ["empty"]


@dataclass(frozen=True)
class SimHashLsh:
    bits: int = 16
    bands: int = 4
    seed: str = "fedkg-semantic-lsh-v1"

    def bucket_names(self, vector: Sequence[float]) -> list[str]:
        if self.bits <= 0:
            raise ValueError("bits must be positive")
        if self.bands <= 0 or self.bits % self.bands != 0:
            raise ValueError("bands must be positive and divide bits")
        signature = "".join("1" if self._projection(bit, vector) >= 0.0 else "0" for bit in range(self.bits))
        band_size = self.bits // self.bands
        return [
            f"lsh:{band}:{signature[band * band_size:(band + 1) * band_size]}"
            for band in range(self.bands)
        ]

    def _projection(self, bit: int, vector: Sequence[float]) -> float:
        total = 0.0
        for index, value in enumerate(vector):
            digest = hashlib.sha256(f"{self.seed}:{bit}:{index}".encode("utf-8")).digest()
            weight = 1.0 if digest[0] & 1 else -1.0
            total += weight * value
        return total
