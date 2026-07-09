"""Embedding adapters compatible with the original SimGRAG configuration."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock


@dataclass
class SentenceTransformerTextEmbedder:
    """Local text embedder using the same SentenceTransformer path as SimGRAG.

    The model is loaded from disk only (`local_files_only=True`) so semantic
    routing does not send private labels to an external embedding service.
    """

    model_path: str | Path
    device: str = "cpu"
    batch_size: int = 64
    _model: object | None = field(default=None, init=False, repr=False)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)
    _cache: dict[str, tuple[float, ...]] = field(default_factory=dict, init=False, repr=False)

    def embed(self, text: object) -> list[float]:
        key = str(text)
        cached = self._cache.get(key)
        if cached is not None:
            return list(cached)
        vector = self.embed_many([key])[0]
        self._cache[key] = tuple(vector)
        return vector

    def embed_many(self, texts: list[object]) -> list[list[float]]:
        if not texts:
            return []
        model = self._load_model()
        string_texts = [str(text) for text in texts]
        with self._lock:
            encoded = model.encode(
                string_texts,
                batch_size=self.batch_size,
                show_progress_bar=False,
            )
        return [self._to_float_list(vector) for vector in encoded]

    def _load_model(self):
        if self._model is None:
            try:
                from sentence_transformers import SentenceTransformer
            except ImportError as exc:
                raise RuntimeError(
                    "sentence-transformers is required for --embedding-backend simgrag"
                ) from exc
            self._model = SentenceTransformer(
                str(self.model_path),
                trust_remote_code=True,
                local_files_only=True,
                device=self.device,
            )
        return self._model

    @staticmethod
    def _to_float_list(vector: object) -> list[float]:
        if hasattr(vector, "tolist"):
            vector = vector.tolist()
        return [float(value) for value in vector]


def embedding_config_from_json(path: str | Path) -> dict[str, object]:
    payload = json.loads(Path(path).read_text())
    config = payload.get("embedding_model")
    if not isinstance(config, dict):
        raise ValueError(f"Missing embedding_model config in {path}")
    return config


def embedder_from_config(
    config_path: str | Path,
    model_path: str | Path | None = None,
    device: str | None = None,
) -> SentenceTransformerTextEmbedder:
    config = embedding_config_from_json(config_path)
    resolved_model_path = model_path or config.get("model_path")
    if not resolved_model_path:
        raise ValueError(f"Missing embedding_model.model_path in {config_path}")
    return SentenceTransformerTextEmbedder(
        model_path=resolved_model_path,
        device=str(device or config.get("device") or "cpu"),
    )
