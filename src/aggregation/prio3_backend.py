"""Subprocess adapter for the isolated Rust/libprio Prio3 implementation."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from src.aggregation.prio3_types import Prio3SumVecRequest, Prio3SumVecResult


class Prio3BackendError(RuntimeError):
    pass


@dataclass(frozen=True)
class Prio3LocalBackend:
    """Run Prio3 locally for protocol validation and benchmarking.

    This adapter deliberately does not implement the existing DPF interface.
    It is an aggregation backend, not a private-lookup backend. The current
    operation reconstructs the aggregate inside one process and must not be
    presented as a network-separated production deployment.
    """

    command: Sequence[str]
    timeout_seconds: float = 60.0

    @classmethod
    def from_executable(
        cls,
        executable: str | Path,
        timeout_seconds: float = 60.0,
    ) -> "Prio3LocalBackend":
        return cls((str(executable),), timeout_seconds=timeout_seconds)

    def capabilities(self) -> Mapping[str, object]:
        return self._call({"op": "capabilities"})

    def sum_vec(self, request: Prio3SumVecRequest) -> Prio3SumVecResult:
        response = self._call(request.as_payload())
        aggregate = response.get("aggregate")
        aggregator_count = response.get("aggregator_count")
        report_count = response.get("report_count")
        if not isinstance(aggregate, list):
            raise Prio3BackendError("Prio3 CLI response must contain an aggregate array")
        try:
            aggregate_values = [self._parse_aggregate_value(value) for value in aggregate]
        except (TypeError, ValueError) as exc:
            raise Prio3BackendError(
                "Prio3 CLI aggregate values must be integers or decimal integer strings"
            ) from exc
        if not isinstance(aggregator_count, int) or isinstance(aggregator_count, bool):
            raise Prio3BackendError("Prio3 CLI response must contain aggregator_count")
        if not isinstance(report_count, int) or isinstance(report_count, bool):
            raise Prio3BackendError("Prio3 CLI response must contain report_count")
        if aggregator_count != request.aggregator_count:
            raise Prio3BackendError("Prio3 CLI returned an unexpected aggregator count")
        if report_count != len(request.measurements):
            raise Prio3BackendError("Prio3 CLI returned an unexpected report count")
        if len(aggregate) != len(request.measurements[0]):
            raise Prio3BackendError("Prio3 CLI returned an unexpected aggregate width")
        return Prio3SumVecResult(aggregate_values, aggregator_count, report_count)

    @staticmethod
    def _parse_aggregate_value(value: object) -> int:
        if isinstance(value, bool):
            raise TypeError("boolean is not an aggregate integer")
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.isascii() and value.isdigit():
            return int(value)
        raise TypeError("invalid aggregate value")

    def _call(self, request: Mapping[str, object]) -> Mapping[str, object]:
        try:
            completed = subprocess.run(
                list(self.command),
                input=json.dumps(request),
                text=True,
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except FileNotFoundError as exc:
            raise Prio3BackendError(f"Prio3 CLI not found: {self.command[0]}") from exc
        except subprocess.TimeoutExpired as exc:
            raise Prio3BackendError("Prio3 CLI timed out") from exc

        if completed.returncode != 0:
            raise Prio3BackendError(
                f"Prio3 CLI failed with exit code {completed.returncode}: {completed.stderr.strip()}"
            )
        try:
            response = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise Prio3BackendError(f"Prio3 CLI returned invalid JSON: {completed.stdout!r}") from exc
        if not isinstance(response, dict):
            raise Prio3BackendError("Prio3 CLI response must be a JSON object")
        return response
