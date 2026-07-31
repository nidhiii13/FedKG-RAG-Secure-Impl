"""Persistent wrapper for the FedKG Lattigo threshold-PIR CLI."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any


class LattigoThresholdPirService:
    """Keep threshold setup and encrypted database state alive across requests."""

    def __init__(
        self,
        *,
        executable: Path,
        records_jsonl: Path,
        record_size: int,
        parties: int,
        threshold: int,
        go_routines: int = 1,
        record_format: str = "bytes",
        plaintext_modulus: int = 65537,
        cwd: Path | None = None,
    ) -> None:
        self._process = subprocess.Popen(
            [
                str(executable),
                "--records-jsonl",
                str(records_jsonl),
                "--record-size",
                str(record_size),
                "--record-format",
                record_format,
                "--parties",
                str(parties),
                "--threshold",
                str(threshold),
                "--go-routines",
                str(go_routines),
                "--plaintext-modulus",
                str(plaintext_modulus),
                "--server-stdin",
            ],
            cwd=str(cwd) if cwd is not None else None,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            text=True,
            bufsize=1,
        )
        self.ready = self._read_json_line()
        if self.ready.get("status") != "ready":
            raise RuntimeError(f"Lattigo threshold-PIR service did not become ready: {self.ready!r}")

    def retrieve(self, indices: list[int]) -> dict[str, Any]:
        if not indices:
            return {"records": []}
        if self._process.stdin is None:
            raise RuntimeError("Lattigo threshold-PIR service stdin is closed")
        self._process.stdin.write(json.dumps({"indices": indices}) + "\n")
        self._process.stdin.flush()
        payload = self._read_json_line()
        if "error" in payload:
            raise RuntimeError(str(payload["error"]))
        return payload

    def retrieve_shared(
        self,
        indices: list[int],
        *,
        share_parties: int,
        share_modulus: int = 65537,
    ) -> dict[str, Any]:
        """Retrieve PIR rows as additive byte shares instead of plaintext JSON.

        This is the bridge primitive for a production pipeline: the response can
        be passed to MPC parties as private inputs. The helper below does not
        parse or decode candidate edges.
        """
        if not indices:
            return {"records": []}
        if share_parties < 2:
            raise ValueError("share_parties must be at least 2")
        if share_modulus < 2:
            raise ValueError("share_modulus must be at least 2")
        if self._process.stdin is None:
            raise RuntimeError("Lattigo threshold-PIR service stdin is closed")
        self._process.stdin.write(
            json.dumps(
                {
                    "indices": indices,
                    "response_mode": "shares",
                    "share_parties": share_parties,
                    "share_modulus": share_modulus,
                }
            )
            + "\n"
        )
        self._process.stdin.flush()
        payload = self._read_json_line()
        if "error" in payload:
            raise RuntimeError(str(payload["error"]))
        return payload

    def close(self) -> None:
        if self._process.poll() is not None:
            return
        if self._process.stdin is not None:
            self._process.stdin.write('{"op":"quit"}\n')
            self._process.stdin.flush()
            self._process.stdin.close()
        try:
            self._process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._process.terminate()
            self._process.wait(timeout=5)

    def _read_json_line(self) -> dict[str, Any]:
        if self._process.stdout is None:
            raise RuntimeError("Lattigo threshold-PIR service stdout is closed")
        while True:
            line = self._process.stdout.readline()
            if line == "":
                stderr = ""
                if self._process.poll() is not None:
                    raise RuntimeError(f"Lattigo threshold-PIR service exited with code {self._process.returncode}")
                continue
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            return json.loads(line)

    def __enter__(self) -> "LattigoThresholdPirService":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()
