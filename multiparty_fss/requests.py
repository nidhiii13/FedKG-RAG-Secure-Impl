"""Evaluator request/response envelopes and the N-party coordinator.

Wire format: docs/wire_format.md. Every envelope binds protocol version,
construction, request ID, evaluator identity, party index, N, t, parameter-set
ID, key-generation ID, domain, output group, universe digest, and (when
projected) the projection digest and slot handles. The coordinator enforces
the complete fail-closed validation matrix of research_and_design.md
section 6.6 before XOR-combining: N is an explicit configuration input and is
never inferred from how many responses happen to arrive.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from multiparty_fss.errors import RequestValidationError, ResponseValidationError
from multiparty_fss.keyshare import MpDpfKeyShare
from multiparty_fss.params import (
    CONSTRUCTION_ID,
    OUTPUT_BITS,
    OUTPUT_GROUP_ID,
    WIRE_VERSION_REQUEST,
    WIRE_VERSION_RESPONSE,
)

_WORD_MASK = (1 << OUTPUT_BITS) - 1
_HEX64_RE = re.compile(r"\A[0-9a-f]{64}\Z")

EVALUATION_DOMAINS = (
    "entity",
    "relation",
    "type",
    "frontier",
    "relation_bucket",
    "entity_bucket",
)

_REQUEST_FIELDS = frozenset(
    {
        "version",
        "construction",
        "request_id",
        "domain",
        "evaluator_id",
        "party_index",
        "party_count",
        "threshold",
        "key_share",
        "projection",
    }
)

_RESPONSE_FIELDS = frozenset(
    {
        "version",
        "construction",
        "request_id",
        "evaluator_id",
        "party_index",
        "party_count",
        "threshold",
        "params_id",
        "keygen_id",
        "domain",
        "output_group",
        "universe_digest",
        "payload_kind",
        "point_count",
        "value_shares",
        "projection_digest",
        "slot_handles",
        "candidate_slot_shares",
    }
)


def _require_nonempty_str(payload: Mapping[str, Any], name: str, exc: type) -> str:
    value = payload.get(name)
    if not isinstance(value, str) or not value:
        raise exc(f"{name} must be a non-empty string")
    return value


def _require_int(payload: Mapping[str, Any], name: str, exc: type) -> int:
    value = payload.get(name)
    if not isinstance(value, int) or isinstance(value, bool):
        raise exc(f"{name} must be an integer")
    return value


@dataclass(frozen=True)
class MpFssEvaluatorRequest:
    request_id: str
    domain: str
    evaluator_id: str
    party_index: int
    party_count: int
    threshold: int
    key_share: MpDpfKeyShare
    projection: Mapping[str, Any] | None  # raw mapping; validated by the service

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": WIRE_VERSION_REQUEST,
            "construction": CONSTRUCTION_ID,
            "request_id": self.request_id,
            "domain": self.domain,
            "evaluator_id": self.evaluator_id,
            "party_index": self.party_index,
            "party_count": self.party_count,
            "threshold": self.threshold,
            "key_share": self.key_share.to_dict(),
            "projection": dict(self.projection) if self.projection is not None else None,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "MpFssEvaluatorRequest":
        exc = RequestValidationError
        if not isinstance(payload, Mapping):
            raise exc("request must be a JSON object")
        if set(payload) != _REQUEST_FIELDS:
            missing = sorted(_REQUEST_FIELDS - set(payload))
            unexpected = sorted(set(payload) - _REQUEST_FIELDS)
            raise exc(f"request fields invalid; missing={missing} unexpected={unexpected}")
        if payload["version"] != WIRE_VERSION_REQUEST:
            raise exc(f"unsupported request version: {payload['version']!r}")
        if payload["construction"] != CONSTRUCTION_ID:
            raise exc(f"unsupported construction: {payload['construction']!r}")
        request_id = _require_nonempty_str(payload, "request_id", exc)
        domain = _require_nonempty_str(payload, "domain", exc)
        if domain not in EVALUATION_DOMAINS:
            raise exc(f"unsupported evaluation domain: {domain!r}")
        evaluator_id = _require_nonempty_str(payload, "evaluator_id", exc)
        party_index = _require_int(payload, "party_index", exc)
        party_count = _require_int(payload, "party_count", exc)
        threshold = _require_int(payload, "threshold", exc)
        key_share = MpDpfKeyShare.from_dict(payload["key_share"])
        if key_share.params.party_count != party_count:
            raise exc("request party_count does not match the key share")
        if key_share.params.threshold != threshold:
            raise exc("request threshold does not match the key share")
        if key_share.party_index != party_index:
            raise exc("request party_index does not match the key share")
        projection = payload["projection"]
        if projection is not None and not isinstance(projection, Mapping):
            raise exc("projection must be an object or null")
        return cls(
            request_id=request_id,
            domain=domain,
            evaluator_id=evaluator_id,
            party_index=party_index,
            party_count=party_count,
            threshold=threshold,
            key_share=key_share,
            projection=projection,
        )


@dataclass(frozen=True)
class MpFssEvaluatorResponse:
    request_id: str
    evaluator_id: str
    party_index: int
    party_count: int
    threshold: int
    params_id: str
    keygen_id: str
    domain: str
    universe_digest: str
    payload_kind: str  # "dense" | "projected"
    point_count: int | None
    value_shares: tuple[int, ...] | None
    projection_digest: str | None
    slot_handles: tuple[str, ...] | None
    candidate_slot_shares: tuple[int, ...] | None

    def __post_init__(self) -> None:
        exc = ResponseValidationError
        if self.payload_kind == "dense":
            if self.point_count is None or self.value_shares is None:
                raise exc("dense response requires point_count and value_shares")
            if self.projection_digest is not None or self.slot_handles is not None:
                raise exc("dense response must not carry projection fields")
            if len(self.value_shares) != self.point_count:
                raise exc("value_shares length does not match point_count")
            values: Sequence[int] = self.value_shares
        elif self.payload_kind == "projected":
            if (
                self.projection_digest is None
                or self.slot_handles is None
                or self.candidate_slot_shares is None
            ):
                raise exc("projected response requires projection fields")
            if self.point_count is not None or self.value_shares is not None:
                raise exc("projected response must not carry dense fields")
            if len(self.candidate_slot_shares) != len(self.slot_handles):
                raise exc("candidate_slot_shares length does not match slot_handles")
            if len(self.slot_handles) != len(set(self.slot_handles)):
                raise exc("slot handles must be unique")
            values = self.candidate_slot_shares
        else:
            raise exc(f"unsupported payload_kind: {self.payload_kind!r}")
        for value in values:
            if not isinstance(value, int) or isinstance(value, bool):
                raise exc("output shares must be integers")
            if not 0 <= value <= _WORD_MASK:
                raise exc("output share out of the 64-bit output group")
        if not _HEX64_RE.match(self.universe_digest):
            raise exc("universe_digest must be 64 hex characters")
        if self.projection_digest is not None and not _HEX64_RE.match(
            self.projection_digest
        ):
            raise exc("projection_digest must be 64 hex characters")
        if self.domain not in EVALUATION_DOMAINS:
            raise exc(f"unsupported evaluation domain: {self.domain!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": WIRE_VERSION_RESPONSE,
            "construction": CONSTRUCTION_ID,
            "request_id": self.request_id,
            "evaluator_id": self.evaluator_id,
            "party_index": self.party_index,
            "party_count": self.party_count,
            "threshold": self.threshold,
            "params_id": self.params_id,
            "keygen_id": self.keygen_id,
            "domain": self.domain,
            "output_group": OUTPUT_GROUP_ID,
            "universe_digest": self.universe_digest,
            "payload_kind": self.payload_kind,
            "point_count": self.point_count,
            "value_shares": list(self.value_shares) if self.value_shares is not None else None,
            "projection_digest": self.projection_digest,
            "slot_handles": list(self.slot_handles) if self.slot_handles is not None else None,
            "candidate_slot_shares": (
                list(self.candidate_slot_shares)
                if self.candidate_slot_shares is not None
                else None
            ),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "MpFssEvaluatorResponse":
        exc = ResponseValidationError
        if not isinstance(payload, Mapping):
            raise exc("response must be a JSON object")
        if set(payload) != _RESPONSE_FIELDS:
            missing = sorted(_RESPONSE_FIELDS - set(payload))
            unexpected = sorted(set(payload) - _RESPONSE_FIELDS)
            raise exc(
                f"response fields invalid; missing={missing} unexpected={unexpected}"
            )
        if payload["version"] != WIRE_VERSION_RESPONSE:
            raise exc(f"unsupported response version: {payload['version']!r}")
        if payload["construction"] != CONSTRUCTION_ID:
            raise exc(f"unsupported construction: {payload['construction']!r}")
        if payload["output_group"] != OUTPUT_GROUP_ID:
            raise exc(f"unsupported output group: {payload['output_group']!r}")

        def opt_int_tuple(name: str) -> tuple[int, ...] | None:
            value = payload[name]
            if value is None:
                return None
            if not isinstance(value, list):
                raise exc(f"{name} must be an array or null")
            return tuple(value)

        def opt_str_tuple(name: str) -> tuple[str, ...] | None:
            value = payload[name]
            if value is None:
                return None
            if not isinstance(value, list) or not all(
                isinstance(item, str) for item in value
            ):
                raise exc(f"{name} must be an array of strings or null")
            return tuple(value)

        point_count = payload["point_count"]
        if point_count is not None and (
            not isinstance(point_count, int) or isinstance(point_count, bool)
        ):
            raise exc("point_count must be an integer or null")
        projection_digest = payload["projection_digest"]
        if projection_digest is not None and not isinstance(projection_digest, str):
            raise exc("projection_digest must be a string or null")
        return cls(
            request_id=_require_nonempty_str(payload, "request_id", exc),
            evaluator_id=_require_nonempty_str(payload, "evaluator_id", exc),
            party_index=_require_int(payload, "party_index", exc),
            party_count=_require_int(payload, "party_count", exc),
            threshold=_require_int(payload, "threshold", exc),
            params_id=_require_nonempty_str(payload, "params_id", exc),
            keygen_id=_require_nonempty_str(payload, "keygen_id", exc),
            domain=_require_nonempty_str(payload, "domain", exc),
            universe_digest=_require_nonempty_str(payload, "universe_digest", exc),
            payload_kind=_require_nonempty_str(payload, "payload_kind", exc),
            point_count=point_count,
            value_shares=opt_int_tuple("value_shares"),
            projection_digest=projection_digest,
            slot_handles=opt_str_tuple("slot_handles"),
            candidate_slot_shares=opt_int_tuple("candidate_slot_shares"),
        )


@dataclass(frozen=True)
class CombinedXorSlots:
    request_id: str
    domain: str
    keygen_id: str
    universe_digest: str
    projection_digest: str | None
    slot_handles: tuple[str, ...]
    values: list[int]

    @property
    def nonzero_slots(self) -> dict[str, int]:
        return {
            slot: value
            for slot, value in zip(self.slot_handles, self.values)
            if value != 0
        }


@dataclass(frozen=True)
class MpFssCoordinator:
    """XOR-combining coordinator for exactly N evaluator responses.

    `party_count` and `threshold` are explicit configuration; the coordinator
    never infers them from the responses it happens to receive.
    """

    party_count: int
    threshold: int

    def combine(
        self,
        responses: Sequence[MpFssEvaluatorResponse],
        expected_request_id: str | None = None,
    ) -> CombinedXorSlots:
        exc = ResponseValidationError
        if len(responses) != self.party_count:
            raise exc(
                f"exactly {self.party_count} evaluator responses are required; "
                f"got {len(responses)}"
            )
        indices = [response.party_index for response in responses]
        if sorted(indices) != list(range(self.party_count)):
            raise exc(
                "responses must carry exactly the party indices "
                f"0..{self.party_count - 1} with no duplicates"
            )
        evaluator_ids = {response.evaluator_id for response in responses}
        if len(evaluator_ids) != self.party_count:
            raise exc("evaluator IDs must be pairwise distinct")
        reference = responses[0]
        if expected_request_id is not None and reference.request_id != expected_request_id:
            raise exc("response request_id does not match the expected request")
        for response in responses:
            if response.party_count != self.party_count:
                raise exc("response party_count does not match the coordinator")
            if response.threshold != self.threshold:
                raise exc("response threshold does not match the coordinator")
            for attribute in (
                "request_id",
                "params_id",
                "keygen_id",
                "domain",
                "universe_digest",
                "payload_kind",
                "projection_digest",
                "slot_handles",
                "point_count",
            ):
                if getattr(response, attribute) != getattr(reference, attribute):
                    raise exc(f"evaluator response mismatch: {attribute}")

        by_index = {response.party_index: response for response in responses}
        if reference.payload_kind == "projected":
            handles = reference.slot_handles or ()
            length = len(handles)
            vectors = {
                index: by_index[index].candidate_slot_shares or ()
                for index in range(self.party_count)
            }
        else:
            handles = ()
            length = reference.point_count or 0
            vectors = {
                index: by_index[index].value_shares or ()
                for index in range(self.party_count)
            }
        combined = [0] * length
        for index in range(self.party_count):
            vector = vectors[index]
            if len(vector) != length:
                raise exc("response share-vector length mismatch")
            for position in range(length):
                combined[position] ^= vector[position]
        return CombinedXorSlots(
            request_id=reference.request_id,
            domain=reference.domain,
            keygen_id=reference.keygen_id,
            universe_digest=reference.universe_digest,
            projection_digest=reference.projection_digest,
            slot_handles=handles,
            values=combined,
        )
