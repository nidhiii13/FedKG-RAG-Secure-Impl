"""Key-share container and strict (de)serialization for the BGI15 p-party DPF.

Wire format: docs/wire_format.md. Every key share binds the full context
required by the task specification: wire-format version, construction
identifier, parameter-set identifier, party count N, claimed threshold t,
party index, input-domain parameters, output-group identifier, PRG identifier,
key-generation (session) identifier, and the domain binding (universe digest
or "raw"). Deserialization is strict: unknown fields, missing fields, wrong
types, wrong payload lengths, and cross-construction payloads are rejected
with KeyShareFormatError. Parsing uses the standard json module plus an
explicit schema walk — no regular expressions.

Sensitive data: `sigma` contains this party's PRG seeds. It is kept in one
immutable bytes object, is never logged, never appears in exception messages,
and is compared/derived only through numpy views. CPython cannot securely
zeroize immutable buffers; see SECURITY.md for the stated limitation.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import Any, Mapping

import numpy as np

from multiparty_fss.errors import KeyShareFormatError
from multiparty_fss.params import (
    CONSTRUCTION_ID,
    OUTPUT_GROUP_ID,
    PRG_ID,
    SEED_BYTES,
    WIRE_VERSION_KEY,
    MpDpfParams,
)

_HEX32_RE = re.compile(r"\A[0-9a-f]{32}\Z")
_HEX64_RE = re.compile(r"\A[0-9a-f]{64}\Z")

DOMAIN_BINDING_RAW = "raw"

_KEY_FIELDS = frozenset(
    {
        "version",
        "construction",
        "params_id",
        "party_count",
        "threshold",
        "party_index",
        "domain_bits",
        "output_group",
        "prg",
        "keygen_id",
        "domain_binding",
        "sigma",
        "correction_words",
    }
)


@dataclass(frozen=True)
class MpDpfKeyShare:
    """One evaluator's key share k_i (Algorithm 3 line 9: sigma_i || cw_1..cw_S)."""

    params: MpDpfParams
    party_index: int
    keygen_id: str
    domain_binding: str
    sigma: bytes
    correction_words: bytes

    def __post_init__(self) -> None:
        if not 0 <= self.party_index < self.params.party_count:
            raise KeyShareFormatError(
                f"party_index must be in [0, {self.params.party_count}); "
                f"got {self.party_index}"
            )
        if not _HEX32_RE.match(self.keygen_id):
            raise KeyShareFormatError("keygen_id must be 32 lowercase hex characters")
        if self.domain_binding != DOMAIN_BINDING_RAW and not _HEX64_RE.match(
            self.domain_binding
        ):
            raise KeyShareFormatError(
                "domain_binding must be 'raw' or a 64-hex universe digest"
            )
        if len(self.sigma) != self.params.sigma_bytes:
            raise KeyShareFormatError(
                "sigma payload length does not match the parameter set"
            )
        if len(self.correction_words) != self.params.cw_bytes:
            raise KeyShareFormatError(
                "correction-word payload length does not match the parameter set"
            )

    # -- typed views used by Eval (zero-copy over the immutable payloads) --

    def seed_blocks(self) -> np.ndarray:
        """(nu, 2^{p-1}, 16) uint8 view of sigma_i; an all-zero block means
        'seed not held' (Algorithm 4 line 6 sentinel)."""
        return np.frombuffer(self.sigma, dtype=np.uint8).reshape(
            self.params.nu, self.params.seeds_per_row, SEED_BYTES
        )

    def cw_matrix(self) -> np.ndarray:
        """(2^{p-1}, mu) uint64 view of cw_1..cw_S (little-endian words)."""
        return np.frombuffer(self.correction_words, dtype="<u8").reshape(
            self.params.seeds_per_row, self.params.mu
        )

    # -- serialization --

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": WIRE_VERSION_KEY,
            "construction": CONSTRUCTION_ID,
            "params_id": self.params.params_id(),
            "party_count": self.params.party_count,
            "threshold": self.params.threshold,
            "party_index": self.party_index,
            "domain_bits": self.params.domain_bits,
            "output_group": OUTPUT_GROUP_ID,
            "prg": PRG_ID,
            "keygen_id": self.keygen_id,
            "domain_binding": self.domain_binding,
            "sigma": base64.b64encode(self.sigma).decode("ascii"),
            "correction_words": base64.b64encode(self.correction_words).decode("ascii"),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "MpDpfKeyShare":
        if not isinstance(payload, Mapping):
            raise KeyShareFormatError("key share must be a JSON object")
        fields = set(payload)
        if fields != _KEY_FIELDS:
            missing = sorted(_KEY_FIELDS - fields)
            unexpected = sorted(fields - _KEY_FIELDS)
            raise KeyShareFormatError(
                f"key share fields invalid; missing={missing} unexpected={unexpected}"
            )
        if payload["version"] != WIRE_VERSION_KEY:
            raise KeyShareFormatError(
                f"unsupported key wire version: {payload['version']!r}"
            )
        if payload["construction"] != CONSTRUCTION_ID:
            raise KeyShareFormatError(
                f"unsupported construction: {payload['construction']!r}"
            )
        if payload["output_group"] != OUTPUT_GROUP_ID:
            raise KeyShareFormatError(
                f"unsupported output group: {payload['output_group']!r}"
            )
        if payload["prg"] != PRG_ID:
            raise KeyShareFormatError(f"unsupported PRG id: {payload['prg']!r}")
        for name in ("party_count", "threshold", "party_index", "domain_bits"):
            value = payload[name]
            if not isinstance(value, int) or isinstance(value, bool):
                raise KeyShareFormatError(f"{name} must be an integer")
        for name in ("params_id", "keygen_id", "domain_binding", "sigma", "correction_words"):
            if not isinstance(payload[name], str):
                raise KeyShareFormatError(f"{name} must be a string")
        try:
            params = MpDpfParams(
                domain_bits=payload["domain_bits"],
                party_count=payload["party_count"],
                threshold=payload["threshold"],
            )
        except Exception as exc:
            raise KeyShareFormatError(f"invalid parameters in key share: {exc}") from exc
        if payload["params_id"] != params.params_id():
            raise KeyShareFormatError("params_id does not match the declared parameters")
        try:
            sigma = base64.b64decode(payload["sigma"], validate=True)
            correction_words = base64.b64decode(payload["correction_words"], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise KeyShareFormatError("key payload is not valid base64") from exc
        return cls(
            params=params,
            party_index=payload["party_index"],
            keygen_id=payload["keygen_id"],
            domain_binding=payload["domain_binding"],
            sigma=sigma,
            correction_words=correction_words,
        )


def serialize_key_share(key_share: MpDpfKeyShare) -> dict[str, Any]:
    """Explicit-API alias (task Phase 6 naming)."""
    return key_share.to_dict()


def deserialize_key_share(payload: Mapping[str, Any]) -> MpDpfKeyShare:
    """Explicit-API alias (task Phase 6 naming)."""
    return MpDpfKeyShare.from_dict(payload)
