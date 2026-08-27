"""Key-share and envelope wire-format tests: round trips and strict rejection."""

from __future__ import annotations

import base64

import pytest

from multiparty_fss.errors import KeyShareFormatError, RequestValidationError
from multiparty_fss.keygen import generate
from multiparty_fss.keyshare import MpDpfKeyShare, deserialize_key_share, serialize_key_share
from multiparty_fss.params import MpDpfParams
from multiparty_fss.requests import MpFssEvaluatorRequest


@pytest.fixture()
def key_share() -> MpDpfKeyShare:
    params = MpDpfParams.create(6, 3, 1)
    return generate(9, 7, 3, 1, params=params)[1]


def test_round_trip(key_share):
    payload = serialize_key_share(key_share)
    restored = deserialize_key_share(payload)
    assert restored == key_share
    assert payload["version"] == "fedkg-mpfss-key-v1"
    assert payload["construction"] == "bgi15-mpdpf-p0"
    assert payload["output_group"] == "xor64"
    assert payload["party_count"] == 3
    assert payload["threshold"] == 1
    assert payload["party_index"] == 1


def test_rejects_missing_field(key_share):
    for field in serialize_key_share(key_share):
        payload = serialize_key_share(key_share)
        del payload[field]
        with pytest.raises(KeyShareFormatError, match="missing"):
            deserialize_key_share(payload)


def test_rejects_unexpected_field(key_share):
    payload = serialize_key_share(key_share)
    payload["extra"] = 1
    with pytest.raises(KeyShareFormatError, match="unexpected"):
        deserialize_key_share(payload)


def test_rejects_wrong_version_and_construction(key_share):
    payload = serialize_key_share(key_share)
    payload["version"] = "fedkg-mpfss-key-v0"
    with pytest.raises(KeyShareFormatError, match="wire version"):
        deserialize_key_share(payload)
    payload = serialize_key_share(key_share)
    payload["construction"] = "bgi16-tree-dpf"
    with pytest.raises(KeyShareFormatError, match="construction"):
        deserialize_key_share(payload)


def test_rejects_wrong_group_and_prg(key_share):
    payload = serialize_key_share(key_share)
    payload["output_group"] = "uint64"  # the two-party additive group
    with pytest.raises(KeyShareFormatError, match="output group"):
        deserialize_key_share(payload)
    payload = serialize_key_share(key_share)
    payload["prg"] = "aes128-mmo"
    with pytest.raises(KeyShareFormatError, match="PRG"):
        deserialize_key_share(payload)


def test_rejects_tampered_params_id(key_share):
    payload = serialize_key_share(key_share)
    payload["params_id"] = "0" * 64
    with pytest.raises(KeyShareFormatError, match="params_id"):
        deserialize_key_share(payload)


def test_rejects_inconsistent_declared_parameters(key_share):
    # party_count changed without recomputing params_id -> params_id mismatch.
    payload = serialize_key_share(key_share)
    payload["party_count"] = 4
    with pytest.raises(KeyShareFormatError):
        deserialize_key_share(payload)
    # threshold inconsistent with N.
    payload = serialize_key_share(key_share)
    payload["threshold"] = 3
    with pytest.raises(KeyShareFormatError):
        deserialize_key_share(payload)
    # unsupported N.
    payload = serialize_key_share(key_share)
    payload["party_count"] = 2
    with pytest.raises(KeyShareFormatError):
        deserialize_key_share(payload)
    payload = serialize_key_share(key_share)
    payload["party_count"] = 11
    with pytest.raises(KeyShareFormatError):
        deserialize_key_share(payload)


def test_rejects_out_of_range_party_index(key_share):
    payload = serialize_key_share(key_share)
    payload["party_index"] = 3
    with pytest.raises(KeyShareFormatError, match="party_index"):
        deserialize_key_share(payload)
    payload["party_index"] = -1
    with pytest.raises(KeyShareFormatError, match="party_index"):
        deserialize_key_share(payload)


def test_rejects_truncated_and_corrupted_payloads(key_share):
    payload = serialize_key_share(key_share)
    sigma = base64.b64decode(payload["sigma"])
    payload["sigma"] = base64.b64encode(sigma[:-16]).decode("ascii")  # truncated
    with pytest.raises(KeyShareFormatError, match="sigma"):
        deserialize_key_share(payload)

    payload = serialize_key_share(key_share)
    payload["correction_words"] = base64.b64encode(b"\x00" * 8).decode("ascii")
    with pytest.raises(KeyShareFormatError, match="correction-word"):
        deserialize_key_share(payload)

    payload = serialize_key_share(key_share)
    payload["sigma"] = "%%%not-base64%%%"
    with pytest.raises(KeyShareFormatError, match="base64"):
        deserialize_key_share(payload)


def test_rejects_malformed_numeric_encodings(key_share):
    payload = serialize_key_share(key_share)
    payload["party_index"] = "1"  # string, not int
    with pytest.raises(KeyShareFormatError, match="integer"):
        deserialize_key_share(payload)
    payload = serialize_key_share(key_share)
    payload["party_count"] = True  # bool is not an int here
    with pytest.raises(KeyShareFormatError, match="integer"):
        deserialize_key_share(payload)


def test_rejects_bad_keygen_id_and_domain_binding(key_share):
    payload = serialize_key_share(key_share)
    payload["keygen_id"] = "xyz"
    with pytest.raises(KeyShareFormatError, match="keygen_id"):
        deserialize_key_share(payload)
    payload = serialize_key_share(key_share)
    payload["domain_binding"] = "not-a-digest"
    with pytest.raises(KeyShareFormatError, match="domain_binding"):
        deserialize_key_share(payload)


def test_legacy_two_party_payload_is_rejected_by_multiparty_parser():
    legacy_payload = {
        # Shape emitted by tools/fss_cli/main.cu ShareJson (two-party path).
        "party": 0,
        "seed": [1, 2, 3, 4],
        "correction_words": [{"s": [0, 0, 0, 0], "tr": False}] * 65,
        "domain_bits": 64,
        "group": "uint64",
        "projection": "hmac_sha256_prefix64",
    }
    with pytest.raises(KeyShareFormatError, match="missing"):
        deserialize_key_share(legacy_payload)


def test_request_round_trip_and_key_binding(key_share):
    request = MpFssEvaluatorRequest(
        request_id="req-1",
        domain="entity",
        evaluator_id="mp0",
        party_index=key_share.party_index,
        party_count=3,
        threshold=1,
        key_share=key_share,
        projection=None,
    )
    restored = MpFssEvaluatorRequest.from_dict(request.to_dict())
    assert restored.key_share == key_share
    assert restored.party_index == 1

    payload = request.to_dict()
    payload["party_index"] = 0  # request metadata no longer matches the key
    with pytest.raises(RequestValidationError, match="party_index"):
        MpFssEvaluatorRequest.from_dict(payload)
    payload = request.to_dict()
    payload["party_count"] = 4
    with pytest.raises(RequestValidationError):
        MpFssEvaluatorRequest.from_dict(payload)
    payload = request.to_dict()
    payload["threshold"] = 2
    with pytest.raises(RequestValidationError, match="threshold"):
        MpFssEvaluatorRequest.from_dict(payload)
    payload = request.to_dict()
    payload["domain"] = "everything"
    with pytest.raises(RequestValidationError, match="domain"):
        MpFssEvaluatorRequest.from_dict(payload)
