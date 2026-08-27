"""Fail-closed behavior of share combination and the response coordinator."""

from __future__ import annotations

import dataclasses

import pytest

from multiparty_fss.combine import combine, combine_vectors
from multiparty_fss.errors import CombineError, ResponseValidationError
from multiparty_fss.evaluate import evaluate
from multiparty_fss.keygen import generate
from multiparty_fss.params import MpDpfParams
from multiparty_fss.requests import MpFssCoordinator, MpFssEvaluatorResponse


def _shares(party_count=3, threshold=1, alpha=5, beta=1):
    params = MpDpfParams.create(5, party_count, threshold)
    return generate(alpha, beta, party_count, threshold, params=params)


def test_combine_rejects_missing_share():
    shares = _shares()
    outputs = {s.party_index: evaluate(s, 5) for s in shares}
    del outputs[1]
    with pytest.raises(CombineError, match="missing=\\[1\\]"):
        combine(outputs, 3)


def test_combine_rejects_extra_share_and_out_of_range_index():
    shares = _shares()
    outputs = {s.party_index: evaluate(s, 5) for s in shares}
    outputs[3] = 12345
    with pytest.raises(CombineError, match="unexpected=\\[3\\]"):
        combine(outputs, 3)


def test_combine_rejects_wrong_party_count():
    shares = _shares()
    outputs = {s.party_index: evaluate(s, 5) for s in shares}
    with pytest.raises(CombineError):
        combine(outputs, 4)


def test_combine_rejects_out_of_group_values():
    with pytest.raises(CombineError, match="64-bit"):
        combine({0: 1 << 64, 1: 0, 2: 0}, 3)
    with pytest.raises(CombineError, match="64-bit"):
        combine({0: -1, 1: 0, 2: 0}, 3)
    with pytest.raises(CombineError, match="integer"):
        combine({0: True, 1: 0, 2: 0}, 3)


def test_combine_vectors_rejects_ragged_vectors():
    with pytest.raises(CombineError, match="same length"):
        combine_vectors({0: [1, 2], 1: [1], 2: [0, 0]}, 3)


def _response(**overrides) -> MpFssEvaluatorResponse:
    base = dict(
        request_id="req-1",
        evaluator_id="mp0",
        party_index=0,
        party_count=3,
        threshold=1,
        params_id="p" * 64,
        keygen_id="k" * 32,
        domain="entity",
        universe_digest="a" * 64,
        payload_kind="projected",
        point_count=None,
        value_shares=None,
        projection_digest="b" * 64,
        slot_handles=("s0", "s1"),
        candidate_slot_shares=(1, 2),
    )
    base.update(overrides)
    return MpFssEvaluatorResponse(**base)


def _response_set(party_count=3):
    return [
        _response(evaluator_id=f"mp{i}", party_index=i, party_count=party_count)
        for i in range(party_count)
    ]


def test_coordinator_combines_three_projected_responses():
    combined = MpFssCoordinator(3, 1).combine(_response_set(), "req-1")
    # XOR of (1,2) three times = (1,2) (odd multiplicity).
    assert combined.values == [1, 2]
    assert combined.slot_handles == ("s0", "s1")


def test_coordinator_rejects_missing_and_extra_responses():
    responses = _response_set()
    with pytest.raises(ResponseValidationError, match="exactly 3"):
        MpFssCoordinator(3, 1).combine(responses[:2])
    with pytest.raises(ResponseValidationError, match="exactly 3"):
        MpFssCoordinator(3, 1).combine(responses + [responses[0]])


def test_coordinator_rejects_duplicate_party_index():
    responses = _response_set()
    responses[2] = dataclasses.replace(responses[2], party_index=0)
    with pytest.raises(ResponseValidationError, match="no duplicates"):
        MpFssCoordinator(3, 1).combine(responses)


def test_coordinator_rejects_duplicate_evaluator_id():
    responses = _response_set()
    responses[2] = dataclasses.replace(responses[2], evaluator_id="mp0")
    with pytest.raises(ResponseValidationError, match="distinct"):
        MpFssCoordinator(3, 1).combine(responses)


def test_coordinator_rejects_wrong_party_count_or_threshold():
    responses = _response_set()
    with pytest.raises(ResponseValidationError, match="exactly 4"):
        MpFssCoordinator(4, 1).combine(responses)
    with pytest.raises(ResponseValidationError, match="threshold"):
        MpFssCoordinator(3, 2).combine(responses)


@pytest.mark.parametrize(
    "attribute,value",
    [
        ("request_id", "req-2"),
        ("keygen_id", "x" * 32),  # mixed key generations
        ("params_id", "q" * 64),  # mixed parameter sets
        ("universe_digest", "c" * 64),
        ("projection_digest", "d" * 64),
        ("domain", "relation"),
    ],
)
def test_coordinator_rejects_mixed_metadata(attribute, value):
    responses = _response_set()
    responses[1] = dataclasses.replace(responses[1], **{attribute: value})
    with pytest.raises(ResponseValidationError, match=attribute):
        MpFssCoordinator(3, 1).combine(responses)


def test_coordinator_rejects_mismatched_expected_request_id():
    with pytest.raises(ResponseValidationError, match="expected request"):
        MpFssCoordinator(3, 1).combine(_response_set(), "another-request")


def test_coordinator_rejects_mixed_slot_handles():
    responses = _response_set()
    responses[1] = dataclasses.replace(responses[1], slot_handles=("s0", "sX"))
    with pytest.raises(ResponseValidationError, match="slot_handles"):
        MpFssCoordinator(3, 1).combine(responses)


def test_response_constructor_rejects_invalid_vectors():
    with pytest.raises(ResponseValidationError, match="length"):
        _response(candidate_slot_shares=(1,))
    with pytest.raises(ResponseValidationError, match="64-bit"):
        _response(candidate_slot_shares=(1, 1 << 64))
    with pytest.raises(ResponseValidationError, match="payload_kind"):
        _response(payload_kind="mystery")
    with pytest.raises(ResponseValidationError, match="dense"):
        _response(payload_kind="dense")  # missing point_count/value_shares
    with pytest.raises(ResponseValidationError, match="universe_digest"):
        _response(universe_digest="short")


def test_wire_response_rejects_mixed_versions_and_constructions():
    payload = _response().to_dict()
    payload["version"] = "fedkg-mpfss-response-v0"
    with pytest.raises(ResponseValidationError, match="version"):
        MpFssEvaluatorResponse.from_dict(payload)
    payload = _response().to_dict()
    payload["construction"] = "something-else"
    with pytest.raises(ResponseValidationError, match="construction"):
        MpFssEvaluatorResponse.from_dict(payload)
    payload = _response().to_dict()
    payload["output_group"] = "uint64"  # two-party additive group
    with pytest.raises(ResponseValidationError, match="output group"):
        MpFssEvaluatorResponse.from_dict(payload)


def test_legacy_projected_response_is_rejected_by_multiparty_parser():
    legacy = {
        # Shape of src/runtime/fss_candidate_projection.py ProjectedFssEvaluatorResponse.
        "request_id": "req-1",
        "evaluator_id": "fss0",
        "evaluator_index": 0,
        "domain": "entity",
        "universe_digest": "a" * 64,
        "projection_digest": "b" * 64,
        "slot_handles": ["s0"],
        "candidate_slot_shares": [5],
    }
    with pytest.raises(ResponseValidationError, match="missing"):
        MpFssEvaluatorResponse.from_dict(legacy)
