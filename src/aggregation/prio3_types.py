"""Typed messages for the optional Prio3 aggregation backend."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class Prio3SumVecRequest:
    """A local Prio3 SumVec protocol run used for integration validation.

    Each measurement is one data party's bounded integer vector. The native
    backend shards every vector among ``aggregator_count`` Prio aggregators,
    executes preparation and aggregation, and reconstructs only the final sum.
    """

    measurements: Sequence[Sequence[int]]
    aggregator_count: int
    bits: int
    context: str = "fedkg-rag/prio3/sumvec/v1"

    def validate(self) -> None:
        if not 2 <= self.aggregator_count <= 255:
            raise ValueError("aggregator_count must be in the range [2, 255]")
        if not 1 <= self.bits < 64:
            raise ValueError("bits must be in the range [1, 63]")
        if not self.measurements:
            raise ValueError("at least one measurement is required")
        width = len(self.measurements[0])
        if width == 0:
            raise ValueError("measurement vectors must not be empty")
        maximum = 1 << self.bits
        for measurement in self.measurements:
            if len(measurement) != width:
                raise ValueError("all measurement vectors must have equal length")
            if any(not isinstance(value, int) or isinstance(value, bool) for value in measurement):
                raise ValueError("measurement values must be integers")
            if any(value < 0 or value >= maximum for value in measurement):
                raise ValueError(f"measurement values must be in [0, 2^{self.bits})")

    def as_payload(self) -> dict[str, object]:
        self.validate()
        return {
            "op": "sum_vec",
            "aggregator_count": self.aggregator_count,
            "bits": self.bits,
            "context": self.context,
            "measurements": [list(measurement) for measurement in self.measurements],
        }


@dataclass(frozen=True)
class Prio3SumVecResult:
    aggregate: list[int]
    aggregator_count: int
    report_count: int
