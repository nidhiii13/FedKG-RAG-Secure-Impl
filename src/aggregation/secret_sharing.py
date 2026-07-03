"""Additive secret sharing utilities for fixed-point candidate scores."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Iterable, List, Sequence

DEFAULT_FIELD = 2**127 - 1
DEFAULT_SCALE = 1_000_000


@dataclass(frozen=True)
class FixedPointEncoder:
    scale: int = DEFAULT_SCALE
    field: int = DEFAULT_FIELD

    def encode(self, value: float) -> int:
        encoded = int(round(value * self.scale))
        return encoded % self.field

    def decode(self, value: int) -> float:
        value %= self.field
        if value > self.field // 2:
            value -= self.field
        return value / self.scale


@dataclass(frozen=True)
class AdditiveSharing:
    field: int = DEFAULT_FIELD

    def share(self, value: int, share_count: int) -> List[int]:
        if share_count < 2:
            raise ValueError("share_count must be at least 2")
        shares = [secrets.randbelow(self.field) for _ in range(share_count - 1)]
        final = (value - sum(shares)) % self.field
        shares.append(final)
        return shares

    def combine(self, shares: Iterable[int]) -> int:
        return sum(shares) % self.field

    def add(self, left: Sequence[int], right: Sequence[int]) -> List[int]:
        if len(left) != len(right):
            raise ValueError("share vectors must have equal length")
        return [(a + b) % self.field for a, b in zip(left, right)]
