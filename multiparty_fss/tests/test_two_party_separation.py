"""Compatibility separation: the two paths must reject each other's material.

- Multi-party wire formats are rejected by the two-party path.
- Two-party wire formats are rejected by the multi-party path
  (covered in test_wire_format.py / test_combine_negative.py and re-checked
  here at the store level).
- The legacy two-party modules still enforce exactly-two semantics
  (behavioral pin; the N-party work must not have relaxed them).
"""

from __future__ import annotations

import pytest

from src.crypto.dpf import DpfKeyShare
from src.runtime.fss_candidate_projection import (
    ProjectedFssCoordinator,
    ProjectedFssEvaluatorResponse,
)
from src.runtime.fss_evaluator_service import (
    FssEvaluatorRequest,
    FssEvaluatorService,
    FssEvaluatorStore,
)
from src.runtime.opaque_index_replication import replicate_opaque_snapshots

from multiparty_fss.errors import KeyShareFormatError, StoreError
from multiparty_fss.keygen import generate
from multiparty_fss.keyshare import deserialize_key_share
from multiparty_fss.params import MpDpfParams
from multiparty_fss.service import MultipartyFssEvaluatorStore


class _NeverCalledBackend:
    def eval(self, key_share, point):  # pragma: no cover - must not be reached
        raise AssertionError("legacy backend must not evaluate multi-party keys")

    def eval_many(self, key_share, points):  # pragma: no cover
        raise AssertionError("legacy backend must not evaluate multi-party keys")


def _multiparty_key_payload():
    params = MpDpfParams.create(4, 3, 1)
    return generate(3, 1, 3, 1, params=params)[0].to_dict()


def test_legacy_service_rejects_multiparty_key_share(tmp_path, snapshot):
    replicate_opaque_snapshots([snapshot], ["fss0", "fss1"], tmp_path)
    store = FssEvaluatorStore.load(tmp_path / "fss0", expected_evaluator_id="fss0")
    service = FssEvaluatorService(store, _NeverCalledBackend())
    # The legacy service checks payload["party"] == evaluator_index; a
    # multi-party payload has no "party" field, so it must be refused before
    # any evaluation happens.
    with pytest.raises(ValueError, match="share index"):
        service.evaluate(
            FssEvaluatorRequest(
                "req-legacy",
                "entity",
                DpfKeyShare("fss0", _multiparty_key_payload()),
            )
        )


def test_legacy_coordinator_still_requires_exactly_two_responses():
    responses = [
        ProjectedFssEvaluatorResponse(
            request_id="r",
            evaluator_id=f"fss{i}",
            evaluator_index=i,
            domain="entity",
            universe_digest="a" * 64,
            projection_digest="b" * 64,
            slot_handles=("s",),
            candidate_slot_shares=[1],
        )
        for i in range(2)
    ]
    combined = ProjectedFssCoordinator().combine(responses)
    assert combined.values == [2]  # additive mod 2^64 — untouched semantics
    with pytest.raises(ValueError, match="exactly two"):
        ProjectedFssCoordinator().combine(responses[:1])


def test_legacy_response_validator_still_pins_indices_to_binary():
    with pytest.raises(ValueError, match="0 or 1"):
        ProjectedFssEvaluatorResponse.from_mapping(
            {
                "request_id": "r",
                "evaluator_id": "fss2",
                "evaluator_index": 2,
                "domain": "entity",
                "universe_digest": "a" * 64,
                "projection_digest": "b" * 64,
                "slot_handles": ["s"],
                "candidate_slot_shares": [1],
            }
        )


def test_legacy_replication_still_requires_exactly_two(tmp_path, snapshot):
    with pytest.raises(ValueError, match="exactly two"):
        replicate_opaque_snapshots([snapshot], ["fss0", "fss1", "fss2"], tmp_path)


def test_multiparty_store_rejects_legacy_layout(tmp_path, snapshot):
    replicate_opaque_snapshots([snapshot], ["fss0", "fss1"], tmp_path)
    with pytest.raises(StoreError, match="manifest version"):
        MultipartyFssEvaluatorStore.load(tmp_path / "fss0")


def test_multiparty_parser_rejects_legacy_key_payload():
    with pytest.raises(KeyShareFormatError):
        deserialize_key_share(
            {
                "party": 1,
                "seed": [9, 9, 9, 8],
                "correction_words": [],
                "domain_bits": 64,
                "group": "uint64",
                "projection": "hmac_sha256_prefix64",
            }
        )
