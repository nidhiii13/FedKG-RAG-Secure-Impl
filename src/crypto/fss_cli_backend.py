"""External CLI adapter for a real FSS/DPF backend.

The adapter expects a command that accepts JSON on stdin and returns JSON on
stdout. This keeps the Python retrieval code independent of whether the real
backend is implemented with myl7/fss, a pybind module, or a standalone binary.

Expected CLI protocol:

Generate:
  stdin:  {"op":"gen","alpha":"...","beta":1,"party_ids":["p0","p1"]}
  stdout: {"shares":{"p0": <json payload>, "p1": <json payload>}}

Evaluate:
  stdin:  {"op":"eval","share": <json payload>, "point":"..."}
  stdout: {"value": 0}
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Mapping, Sequence

from src.crypto.dpf import DpfKeyShare


class FssCliBackendError(RuntimeError):
    pass


@dataclass(frozen=True)
class FssCliBackend:
    command: Sequence[str]
    timeout_seconds: float = 30.0
    max_eval_batch_size: int = 256

    @classmethod
    def from_executable(
        cls,
        executable: str | Path,
        timeout_seconds: float = 30.0,
        max_eval_batch_size: int = 256,
    ) -> "FssCliBackend":
        return cls((str(executable),), timeout_seconds=timeout_seconds, max_eval_batch_size=max_eval_batch_size)

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
            raise FssCliBackendError(f"FSS/DPF CLI not found: {self.command[0]}") from exc
        except subprocess.TimeoutExpired as exc:
            raise FssCliBackendError("FSS/DPF CLI timed out") from exc

        if completed.returncode != 0:
            raise FssCliBackendError(
                "FSS/DPF CLI failed with exit code "
                f"{completed.returncode}: {completed.stderr.strip()}"
            )
        try:
            return json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise FssCliBackendError(
                f"FSS/DPF CLI returned invalid JSON: {completed.stdout!r}"
            ) from exc

    def gen(self, alpha: str, beta: int, party_ids: Sequence[str]) -> Dict[str, DpfKeyShare]:
        response = self._call(
            {"op": "gen", "alpha": alpha, "beta": beta, "party_ids": list(party_ids)}
        )
        shares = response.get("shares")
        if not isinstance(shares, dict):
            raise FssCliBackendError("FSS/DPF CLI gen response must contain a shares object")
        missing = set(party_ids) - set(shares)
        if missing:
            raise FssCliBackendError(f"FSS/DPF CLI omitted shares for parties: {sorted(missing)}")
        return {party_id: DpfKeyShare(party_id, shares[party_id]) for party_id in party_ids}

    def eval(self, key_share: DpfKeyShare, point: str) -> int:
        response = self._call({"op": "eval", "share": key_share.payload, "point": point})
        value = response.get("value")
        if not isinstance(value, int):
            raise FssCliBackendError("FSS/DPF CLI eval response must contain an integer value")
        return value

    def eval_many(self, key_share: DpfKeyShare, points: Sequence[str]) -> list[int]:
        point_list = list(points)
        if not point_list:
            return []
        values: list[int] = []
        batch_size = max(1, self.max_eval_batch_size)
        for offset in range(0, len(point_list), batch_size):
            batch = point_list[offset : offset + batch_size]
            values.extend(self._eval_many_batch(key_share, batch))
        return values

    def _eval_many_batch(self, key_share: DpfKeyShare, points: Sequence[str]) -> list[int]:
        try:
            response = self._call({"op": "eval_many", "share": key_share.payload, "points": list(points)})
        except FssCliBackendError:
            if len(points) <= 1:
                raise
            midpoint = len(points) // 2
            return self._eval_many_batch(key_share, points[:midpoint]) + self._eval_many_batch(key_share, points[midpoint:])

        values = response.get("values")
        if not isinstance(values, list) or not all(isinstance(value, int) for value in values):
            raise FssCliBackendError("FSS/DPF CLI eval_many response must contain an integer values array")
        if len(values) != len(points):
            raise FssCliBackendError("FSS/DPF CLI eval_many response length does not match request")
        return values
