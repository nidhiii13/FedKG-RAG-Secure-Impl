"""SealPIR/lattice-PIR backend adapter.

This module intentionally does not implement lattice PIR in Python. It defines
the boundary to a native PIR backend such as SealPIR/FastPIR/Spiral: Python
builds fixed encoded KG bucket records, while the native backend performs
encrypted index query generation, server answer generation, and client decode.
"""

from __future__ import annotations

import base64
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Sequence


class SealPirBackendError(RuntimeError):
    pass


@dataclass(frozen=True)
class SealPirDatabaseConfig:
    database_size: int
    record_size: int
    label: str = "fedkg-sealpir-bucket-db"


@dataclass(frozen=True)
class SealPirQuery:
    client_state: bytes
    request: bytes


@dataclass(frozen=True)
class SealPirAnswer:
    response: bytes


class SealPirBackend(Protocol):
    def setup(self, records: Sequence[bytes], config: SealPirDatabaseConfig) -> bytes:
        """Return serialized server state for the encoded fixed-record database."""

    def query(self, index: int, config: SealPirDatabaseConfig) -> SealPirQuery:
        """Return client state and encrypted PIR request for a hidden record index."""

    def answer(self, server_state: bytes, request: bytes) -> SealPirAnswer:
        """Return encrypted PIR server response."""

    def decode(self, client_state: bytes, answer: SealPirAnswer) -> bytes:
        """Decode the selected record from the encrypted server response."""


class UnconfiguredSealPirBackend:
    """Placeholder used when no native SealPIR backend is installed."""

    def setup(self, records: Sequence[bytes], config: SealPirDatabaseConfig) -> bytes:
        raise SealPirBackendError(_missing_backend_message())

    def query(self, index: int, config: SealPirDatabaseConfig) -> SealPirQuery:
        raise SealPirBackendError(_missing_backend_message())

    def answer(self, server_state: bytes, request: bytes) -> SealPirAnswer:
        raise SealPirBackendError(_missing_backend_message())

    def decode(self, client_state: bytes, answer: SealPirAnswer) -> bytes:
        raise SealPirBackendError(_missing_backend_message())


class SealPirCliBackend:
    """JSON-over-stdin adapter for a native SealPIR-style CLI."""

    def __init__(self, executable: Path, *, timeout_seconds: float = 120.0) -> None:
        self.executable = executable
        self.timeout_seconds = timeout_seconds

    def setup(self, records: Sequence[bytes], config: SealPirDatabaseConfig) -> bytes:
        response = self._call(
            {
                "op": "setup",
                "config": _config_payload(config),
                "records_b64": [_b64(record) for record in records],
            }
        )
        return _unb64(response["server_state_b64"])

    def query(self, index: int, config: SealPirDatabaseConfig) -> SealPirQuery:
        response = self._call(
            {
                "op": "query",
                "index": index,
                "config": _config_payload(config),
            }
        )
        return SealPirQuery(
            client_state=_unb64(response["client_state_b64"]),
            request=_unb64(response["request_b64"]),
        )

    def answer(self, server_state: bytes, request: bytes) -> SealPirAnswer:
        response = self._call(
            {
                "op": "answer",
                "server_state_b64": _b64(server_state),
                "request_b64": _b64(request),
            }
        )
        return SealPirAnswer(response=_unb64(response["response_b64"]))

    def decode(self, client_state: bytes, answer: SealPirAnswer) -> bytes:
        response = self._call(
            {
                "op": "decode",
                "client_state_b64": _b64(client_state),
                "response_b64": _b64(answer.response),
            }
        )
        return _unb64(response["record_b64"]).rstrip(b"\x00")

    def _call(self, payload: dict[str, object]) -> dict[str, object]:
        if not self.executable.exists():
            raise SealPirBackendError(
                f"SealPIR CLI not found: {self.executable}. {_missing_backend_message()}"
            )
        completed = subprocess.run(
            [str(self.executable)],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            timeout=self.timeout_seconds,
            check=False,
        )
        if completed.returncode != 0:
            raise SealPirBackendError(
                f"SealPIR CLI failed with exit code {completed.returncode}: {completed.stderr}"
            )
        try:
            response = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise SealPirBackendError("SealPIR CLI returned invalid JSON") from exc
        if not isinstance(response, dict):
            raise SealPirBackendError("SealPIR CLI response must be a JSON object")
        return response


def _config_payload(config: SealPirDatabaseConfig) -> dict[str, object]:
    return {
        "database_size": config.database_size,
        "record_size": config.record_size,
        "label": config.label,
    }


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: object) -> bytes:
    if not isinstance(value, str):
        raise SealPirBackendError("expected base64 string")
    return base64.b64decode(value.encode("ascii"))


def _missing_backend_message() -> str:
    return (
        "A native SealPIR/FastPIR/Spiral-compatible backend is required. "
        "This adapter defines the integration boundary but does not implement "
        "lattice PIR in Python."
    )
