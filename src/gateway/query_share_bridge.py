"""Local MPC-style query share bridge.

This module models the boundary where a query gateway secret-shares encoded
query tokens to an MPC committee before a specialized private lookup backend is
invoked. The current implementation is local validation code: it creates and
checks additive shares in-process, then returns the encoded tokens needed by the
existing DPF/FSS lookup backend.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Iterable, Sequence

from src.aggregation.secret_sharing import AdditiveSharing
from src.crypto.hmac_ids import HmacIdProvider


UNKNOWN_PREFIX = "UNKNOWN"


@dataclass(frozen=True)
class SharedQueryToken:
    namespace: str
    label: str
    encoded_id: str | None
    shares: tuple[int, ...]
    share_commitments: tuple[str, ...]

    @property
    def is_unknown(self) -> bool:
        return self.encoded_id is None


@dataclass(frozen=True)
class QueryShareBridgeResult:
    share_count: int
    field: int
    tokens: tuple[SharedQueryToken, ...]

    @property
    def token_count(self) -> int:
        return len(self.tokens)

    @property
    def non_unknown_token_count(self) -> int:
        return sum(not token.is_unknown for token in self.tokens)

    def public_metadata(self) -> dict[str, object]:
        return {
            "mode": "local-mpc-query-share-validation",
            "share_count": self.share_count,
            "field_bits": self.field.bit_length(),
            "token_count": self.token_count,
            "non_unknown_token_count": self.non_unknown_token_count,
            "token_commitments": [
                {
                    "namespace": token.namespace,
                    "is_unknown": token.is_unknown,
                    "share_commitments": list(token.share_commitments),
                }
                for token in self.tokens
            ],
            "production_requirement": (
                "replace local share verification with network-separated MPC "
                "parties retaining query shares across lookup/ranking"
            ),
        }


class MpcQueryShareBridge:
    """Encode query graph atoms and split them into additive shares."""

    def __init__(
        self,
        ids: HmacIdProvider,
        *,
        share_count: int,
        sharing: AdditiveSharing | None = None,
    ) -> None:
        if share_count < 2:
            raise ValueError("share_count must be at least 2")
        self.ids = ids
        self.share_count = share_count
        self.sharing = sharing or AdditiveSharing()

    def share_edges(self, edges: Sequence[tuple[str, str, str]]) -> QueryShareBridgeResult:
        tokens: list[SharedQueryToken] = []
        for source, relation, target in edges:
            tokens.append(self._share_atom("entity", source))
            tokens.append(self._share_atom("relation", relation))
            tokens.append(self._share_atom("entity", target))
        self._verify(tokens)
        return QueryShareBridgeResult(
            share_count=self.share_count,
            field=self.sharing.field,
            tokens=tuple(tokens),
        )

    def _share_atom(self, namespace: str, label: str) -> SharedQueryToken:
        if _is_unknown(label):
            shares = tuple(0 for _ in range(self.share_count))
            encoded_id = None
        else:
            encoded_id = self.ids.id_for(namespace, label)
            value = int(encoded_id, 16) % self.sharing.field
            shares = tuple(self.sharing.share(value, self.share_count))
        return SharedQueryToken(
            namespace=namespace,
            label=label,
            encoded_id=encoded_id,
            shares=shares,
            share_commitments=tuple(_commit_share(share) for share in shares),
        )

    def _verify(self, tokens: Iterable[SharedQueryToken]) -> None:
        for token in tokens:
            if token.encoded_id is None:
                if self.sharing.combine(token.shares) != 0:
                    raise ValueError("UNKNOWN token shares must combine to zero")
                continue
            expected = int(token.encoded_id, 16) % self.sharing.field
            actual = self.sharing.combine(token.shares)
            if actual != expected:
                raise ValueError("query token shares failed local reconstruction check")


def _is_unknown(value: str) -> bool:
    return value.strip().upper().startswith(UNKNOWN_PREFIX)


def _commit_share(value: int) -> str:
    return hashlib.sha256(str(value).encode("ascii")).hexdigest()
