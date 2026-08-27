"""Rank-domain encoding over the shared opaque evaluation universe.

The multi-party DPF's input domain is [0, 2^n) where n = ceil(log2(U)) for a
shared universe of U opaque points (research_and_design.md section 6.4). The
DPF input for a point is its rank in the SORTED universe list; the queried
alpha is the rank of the queried opaque ID. The universe (hence the rank
mapping) is public to all protocol participants and is bound into keys,
requests, and responses through the universe digest.

The digest algorithm is reused from the legacy path
(src/runtime/fss_evaluator_service.py: universe_digest) so that "same
universe" means the same thing on both paths; every other wire artifact is
version-disjoint. The digest is a hash of public data — sharing it leaks
nothing new.

Unlike the legacy path, the multi-party path does NOT truncate identifiers to
64 bits: ranks index the full opaque IDs, so the 64-bit projection-collision
concern (src/crypto/dpf_domain.py) does not apply here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from src.runtime.fss_evaluator_service import universe_digest

from multiparty_fss.errors import DomainError
from multiparty_fss.params import MpDpfParams, domain_bits_for_universe


@dataclass(frozen=True)
class UniverseDomain:
    """A validated, sorted shared universe with rank encoding."""

    points: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.points:
            raise DomainError("universe must contain at least one point")
        if list(self.points) != sorted(set(self.points)):
            raise DomainError("universe points must be sorted and unique")
        for point in self.points:
            if not isinstance(point, str) or len(point) % 2 != 0 or not point:
                raise DomainError("universe points must be even-length hex strings")
            if any(ch not in "0123456789abcdef" for ch in point):
                raise DomainError("universe points must be lowercase hex strings")

    @classmethod
    def from_points(cls, points: Sequence[str]) -> "UniverseDomain":
        return cls(tuple(sorted(set(points))))

    @property
    def size(self) -> int:
        return len(self.points)

    @property
    def domain_bits(self) -> int:
        return domain_bits_for_universe(self.size)

    def digest(self) -> str:
        return universe_digest(list(self.points))

    def rank_of(self, point: str) -> int | None:
        """0-based rank of `point`, or None if it is not in the universe."""
        import bisect

        index = bisect.bisect_left(self.points, point)
        if index < len(self.points) and self.points[index] == point:
            return index
        return None

    def params(self, party_count: int, threshold: int | None = None) -> MpDpfParams:
        return MpDpfParams.create(self.domain_bits, party_count, threshold)
