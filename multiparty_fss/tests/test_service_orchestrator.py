"""Integration: N-store replication, evaluator services, and the orchestrator.

Covers: N replicated opaque stores, N role-separated evaluator services,
candidate projection over N output shares, end-to-end exact private lookup,
fail-closed behavior with missing/misconfigured evaluators, and universe
binding enforcement.
"""

from __future__ import annotations

import pytest

from src.aggregation.prio3_candidates import SessionCandidateHandleProvider

from multiparty_fss.errors import RequestValidationError, StoreError
from multiparty_fss.keygen import generate
from multiparty_fss.orchestrator import MultipartyFssQueryOrchestrator
from multiparty_fss.params import MpDpfParams, domain_bits_for_universe
from multiparty_fss.replication import (
    replicate_opaque_snapshots_multiparty,
    verify_multiparty_replicas,
)
from multiparty_fss.requests import MpFssEvaluatorRequest
from multiparty_fss.service import (
    MultipartyFssEvaluatorService,
    MultipartyFssEvaluatorStore,
)

HANDLE_PROVIDER = SessionCandidateHandleProvider(
    b"0123456789abcdef", b"nonce-0123456789"
)


def _evaluator_ids(count: int) -> list[str]:
    return [f"mp_fss_{index}" for index in range(count)]


def _build_stores(tmp_path, snapshots, count, threshold=None):
    manifests = replicate_opaque_snapshots_multiparty(
        snapshots, _evaluator_ids(count), tmp_path, threshold=threshold
    )
    verify_multiparty_replicas(manifests)
    return [
        MultipartyFssEvaluatorStore.load(
            tmp_path / evaluator_id, expected_evaluator_id=evaluator_id
        )
        for evaluator_id in _evaluator_ids(count)
    ]


@pytest.mark.parametrize("party_count,threshold", [(3, 1), (4, 1), (5, 2), (7, 3)])
def test_end_to_end_exact_lookup(tmp_path, snapshot, ids, party_count, threshold):
    stores = _build_stores(tmp_path, [snapshot], party_count, threshold)
    services = [MultipartyFssEvaluatorService(store) for store in stores]
    orchestrator = MultipartyFssQueryOrchestrator(services, HANDLE_PROVIDER)

    alice = ids.entity_id("Alice")
    result = orchestrator.query("req-hit", "entity", alice, capacity=16)
    assert result.party_count == party_count
    assert result.threshold == threshold
    assert result.alpha_in_universe
    assert list(result.candidate_values.values()) == [1]
    (candidate_id,) = result.candidate_values
    assert candidate_id == alice  # the raw opaque entity ID

    # A queried ID absent from the universe reconstructs all-zero (miss),
    # via the zero-function keys — not an error, no leakage through failure.
    result_miss = orchestrator.query("req-miss", "entity", "ff" * 32, capacity=16)
    assert not result_miss.alpha_in_universe
    assert result_miss.candidate_values == {}
    assert all(value == 0 for value in result_miss.combined.values)


def test_multi_partition_universe_union(tmp_path, snapshot, second_snapshot, ids):
    stores = _build_stores(tmp_path, [snapshot, second_snapshot], 3)
    services = [MultipartyFssEvaluatorService(store) for store in stores]
    orchestrator = MultipartyFssQueryOrchestrator(services, HANDLE_PROVIDER)
    erin = ids.entity_id("Erin")  # lives in the second partition
    result = orchestrator.query("req-2", "entity", erin, capacity=32)
    assert list(result.candidate_values.values()) == [1]


def test_replication_rejects_two_evaluators_and_duplicates(tmp_path, snapshot):
    with pytest.raises(StoreError, match="legacy"):
        replicate_opaque_snapshots_multiparty([snapshot], ["a", "b"], tmp_path)
    with pytest.raises(StoreError, match="unique"):
        replicate_opaque_snapshots_multiparty([snapshot], ["a", "a", "b"], tmp_path)
    with pytest.raises(StoreError, match="threshold"):
        replicate_opaque_snapshots_multiparty(
            [snapshot], ["a", "b", "c"], tmp_path, threshold=3
        )


def test_store_binds_identity_and_topology(tmp_path, snapshot):
    _build_stores(tmp_path, [snapshot], 3)
    with pytest.raises(StoreError, match="identity"):
        MultipartyFssEvaluatorStore.load(
            tmp_path / "mp_fss_0", expected_evaluator_id="mp_fss_1"
        )
    store = MultipartyFssEvaluatorStore.load(tmp_path / "mp_fss_2")
    assert store.party_index == 2
    assert store.party_count == 3
    assert store.threshold == 1
    assert store.evaluator_ids == ("mp_fss_0", "mp_fss_1", "mp_fss_2")


def test_legacy_two_party_store_is_rejected(tmp_path, snapshot):
    from src.runtime.opaque_index_replication import replicate_opaque_snapshots

    replicate_opaque_snapshots([snapshot], ["fss0", "fss1"], tmp_path)
    with pytest.raises(StoreError, match="manifest version"):
        MultipartyFssEvaluatorStore.load(tmp_path / "fss0")


def test_orchestrator_fails_closed_on_missing_evaluator(tmp_path, snapshot, ids):
    stores = _build_stores(tmp_path, [snapshot], 3)
    services = [MultipartyFssEvaluatorService(store) for store in stores]
    orchestrator = MultipartyFssQueryOrchestrator(services[:2], HANDLE_PROVIDER)
    with pytest.raises(StoreError, match="exactly 3"):
        orchestrator.query("req", "entity", ids.entity_id("Alice"), capacity=16)


def test_orchestrator_rejects_duplicate_store(tmp_path, snapshot, ids):
    stores = _build_stores(tmp_path, [snapshot], 3)
    services = [MultipartyFssEvaluatorService(store) for store in stores]
    orchestrator = MultipartyFssQueryOrchestrator(
        [services[0], services[1], services[1]], HANDLE_PROVIDER
    )
    with pytest.raises(StoreError, match="exactly once"):
        orchestrator.query("req", "entity", ids.entity_id("Alice"), capacity=16)


def test_service_rejects_misaddressed_and_misbound_requests(tmp_path, snapshot, ids):
    stores = _build_stores(tmp_path, [snapshot], 3)
    service0 = MultipartyFssEvaluatorService(stores[0])
    universe = stores[0].universe("entity")
    params = MpDpfParams.create(universe.domain_bits, 3, 1)
    alpha = universe.rank_of(ids.entity_id("Alice"))
    shares = generate(alpha, 1, 3, 1, params=params, domain_binding=universe.digest())

    def request_for(key_share, **overrides):
        base = dict(
            request_id="req-x",
            domain="entity",
            evaluator_id="mp_fss_0",
            party_index=key_share.party_index,
            party_count=3,
            threshold=1,
            key_share=key_share,
            projection=None,
        )
        base.update(overrides)
        return MpFssEvaluatorRequest(**base)

    # wrong evaluator: key/request for party 1 sent to evaluator 0
    with pytest.raises(RequestValidationError, match="party_index"):
        service0.evaluate(request_for(shares[1], evaluator_id="mp_fss_0"))
    # wrong evaluator id
    with pytest.raises(RequestValidationError, match="different evaluator"):
        service0.evaluate(request_for(shares[0], evaluator_id="mp_fss_1"))
    # unbound ("raw") key is refused by the service
    raw_shares = generate(alpha, 1, 3, 1, params=params)
    with pytest.raises(RequestValidationError, match="not bound"):
        service0.evaluate(request_for(raw_shares[0]))
    # bound to a different universe digest
    wrong_binding = generate(
        alpha, 1, 3, 1, params=params, domain_binding="e" * 64
    )
    with pytest.raises(RequestValidationError, match="universe binding"):
        service0.evaluate(request_for(wrong_binding[0]))
    # wrong domain_bits for this universe
    bad_params = MpDpfParams.create(universe.domain_bits + 1, 3, 1)
    bad_shares = generate(
        alpha, 1, 3, 1, params=bad_params, domain_binding=universe.digest()
    )
    with pytest.raises(RequestValidationError, match="domain_bits"):
        service0.evaluate(request_for(bad_shares[0]))
    # wrong topology metadata vs the store manifest
    with pytest.raises(RequestValidationError, match="party_count"):
        four_party = generate(
            alpha,
            1,
            4,
            1,
            domain_bits=universe.domain_bits,
            domain_binding=universe.digest(),
        )
        service0.evaluate(
            request_for(four_party[0], party_count=4, threshold=1)
        )


def test_dense_and_projected_responses_are_consistent(tmp_path, snapshot, ids):
    stores = _build_stores(tmp_path, [snapshot], 3)
    services = [MultipartyFssEvaluatorService(store) for store in stores]
    universe = stores[0].universe("entity")
    params = MpDpfParams.create(universe.domain_bits, 3, 1)
    alice = ids.entity_id("Alice")
    alpha = universe.rank_of(alice)
    shares = generate(alpha, 1, 3, 1, params=params, domain_binding=universe.digest())
    dense = []
    for service, key_share in zip(services, shares):
        response = service.evaluate(
            MpFssEvaluatorRequest(
                request_id="req-dense",
                domain="entity",
                evaluator_id=service.store.evaluator_id,
                party_index=key_share.party_index,
                party_count=3,
                threshold=1,
                key_share=key_share,
                projection=None,
            )
        )
        assert response.payload_kind == "dense"
        assert response.point_count == universe.size
        dense.append(response)
    combined = [0] * universe.size
    for response in dense:
        for position, value in enumerate(response.value_shares):
            combined[position] ^= value
    expected = [0] * universe.size
    expected[alpha] = 1
    assert combined == expected


def test_universe_digest_divergence_fails_closed(tmp_path, snapshot, second_snapshot):
    # Build two inconsistent "replicas" by hand: same topology, different data.
    first = replicate_opaque_snapshots_multiparty(
        [snapshot], _evaluator_ids(3), tmp_path / "a"
    )
    second = replicate_opaque_snapshots_multiparty(
        [second_snapshot], _evaluator_ids(3), tmp_path / "b"
    )
    with pytest.raises(StoreError, match="not identical"):
        verify_multiparty_replicas(
            {
                "mp_fss_0": first["mp_fss_0"],
                "mp_fss_1": second["mp_fss_1"],
                "mp_fss_2": first["mp_fss_2"],
            }
        )
    stores = [
        MultipartyFssEvaluatorStore.load((tmp_path / "a") / "mp_fss_0"),
        MultipartyFssEvaluatorStore.load((tmp_path / "b") / "mp_fss_1"),
        MultipartyFssEvaluatorStore.load((tmp_path / "a") / "mp_fss_2"),
    ]
    services = [MultipartyFssEvaluatorService(store) for store in stores]
    orchestrator = MultipartyFssQueryOrchestrator(services, HANDLE_PROVIDER)
    with pytest.raises(StoreError, match="different universes"):
        orchestrator.query("req", "entity", "ab" * 32, capacity=64)


def test_manifest_tamper_detection(tmp_path, snapshot):
    import json

    _build_stores(tmp_path, [snapshot], 3)
    manifest_path = tmp_path / "mp_fss_1" / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["party_index"] = 0  # inconsistent with evaluator_ids order
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(StoreError, match="party_index"):
        MultipartyFssEvaluatorStore.load(tmp_path / "mp_fss_1")

    manifest["party_index"] = 1
    manifest["snapshots"][0]["digest"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(StoreError, match="digest"):
        MultipartyFssEvaluatorStore.load(tmp_path / "mp_fss_1")


def test_domain_bits_matches_universe_helper(snapshot):
    from src.party.opaque_index_snapshot import ReplicatedEvaluatorIndex

    index = ReplicatedEvaluatorIndex((snapshot,))
    count = len(index.entity_points)
    assert domain_bits_for_universe(count) == max(count - 1, 1).bit_length()
