"""Minimal TCP transport for process-separated evaluator deployment.

Framing: 8-byte big-endian length prefix followed by exactly that many bytes
of UTF-8 JSON. One request/response exchange per connection (stateless
servers; a TCP handshake per lookup is included in measured deployed-mode
latency, which is the honest accounting for this prototype).

Security posture: this transport provides NO confidentiality and NO
authentication — it exists so that evaluation can measure real marshaling +
IPC/network costs with genuinely separated evaluator processes.
SECURITY.md's deployment assumption (mutually authenticated confidential
channels, e.g. mTLS) is unchanged and NOT satisfied by this module; do not
use it outside localhost evaluation.

Message validation is entirely delegated to the existing fail-closed wire
layer (multiparty_fss.requests / service): the server parses the request with
MpFssEvaluatorRequest.from_dict and returns either a response object or
{"error": "..."} with no partial state.
"""

from __future__ import annotations

import json
import socket
from dataclasses import dataclass

from multiparty_fss.errors import MultipartyFssError, ResponseValidationError

_LENGTH_BYTES = 8
MAX_MESSAGE_BYTES = 256 * 1024 * 1024


def send_message(sock: socket.socket, payload: dict) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_MESSAGE_BYTES:
        raise MultipartyFssError("message exceeds the transport size cap")
    sock.sendall(len(body).to_bytes(_LENGTH_BYTES, "big") + body)


def recv_message(sock: socket.socket) -> dict:
    header = _recv_exact(sock, _LENGTH_BYTES)
    length = int.from_bytes(header, "big")
    if length > MAX_MESSAGE_BYTES:
        raise MultipartyFssError("peer announced a message exceeding the size cap")
    body = _recv_exact(sock, length)
    payload = json.loads(body.decode("utf-8"))
    if not isinstance(payload, dict):
        raise MultipartyFssError("transport messages must be JSON objects")
    return payload


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    chunks = []
    remaining = count
    while remaining:
        chunk = sock.recv(min(remaining, 1 << 20))
        if not chunk:
            raise MultipartyFssError("peer closed the connection mid-message")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


@dataclass(frozen=True)
class SocketEvaluatorClient:
    """Client for one remote evaluator process."""

    host: str
    port: int
    timeout_seconds: float = 120.0

    def evaluate(self, request_payload: dict) -> dict:
        with socket.create_connection((self.host, self.port), self.timeout_seconds) as sock:
            send_message(sock, request_payload)
            response = recv_message(sock)
        if "error" in response:
            raise ResponseValidationError(
                f"evaluator {self.host}:{self.port} refused the request: "
                f"{response['error']}"
            )
        return response
