"""Tests for the evaluation baselines and the socket transport.

The baselines are comparison references only (see baselines.py); these tests
pin their functional correctness so benchmark numbers are meaningful. The
transport test runs a real process-separated evaluator server on an ephemeral
localhost port.
"""

from __future__ import annotations

import json
import secrets
import subprocess
import sys
from pathlib import Path

import pytest

from multiparty_fss.baselines import NaiveXorSharing, PlaintextLookup, TreeDpf2Party
from multiparty_fss.domain import UniverseDomain
from multiparty_fss.errors import ParameterError, ResponseValidationError
from multiparty_fss.keygen import generate
from multiparty_fss.replication import replicate_opaque_snapshots_multiparty
from multiparty_fss.requests import MpFssCoordinator, MpFssEvaluatorRequest, MpFssEvaluatorResponse
from multiparty_fss.service import MultipartyFssEvaluatorStore
from multiparty_fss.transport import SocketEvaluatorClient

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("domain_bits", [1, 3, 6, 9])
def test_tree_dpf_exhaustive(domain_bits):
    dpf = TreeDpf2Party(domain_bits)
    for _ in range(3):
        alpha = secrets.randbelow(1 << domain_bits)
        beta = secrets.randbits(64)
        key0, key1 = dpf.generate(alpha, beta)
        for x in range(1 << domain_bits):
            combined = dpf.combine(dpf.evaluate(key0, x), dpf.evaluate(key1, x))
            assert combined == (beta if x == alpha else 0)


def test_tree_dpf_full_matches_scalar_and_partial_universe():
    dpf = TreeDpf2Party(7)
    key0, key1 = dpf.generate(77, 12345)
    for key in (key0, key1):
        full = dpf.evaluate_full(key, 128)
        assert [int(v) for v in full] == [dpf.evaluate(key, x) for x in range(128)]
        partial = dpf.evaluate_full(key, 100)
        assert [int(v) for v in partial] == [dpf.evaluate(key, x) for x in range(100)]


def test_tree_dpf_beta_edges_and_validation():
    dpf = TreeDpf2Party(5)
    for beta in (0, 1, (1 << 64) - 1):
        key0, key1 = dpf.generate(3, beta)
        assert dpf.combine(dpf.evaluate(key0, 3), dpf.evaluate(key1, 3)) == beta
        assert dpf.combine(dpf.evaluate(key0, 4), dpf.evaluate(key1, 4)) == 0
    with pytest.raises(ParameterError):
        dpf.generate(1 << 5, 1)
    with pytest.raises(ParameterError):
        dpf.generate(0, 1 << 64)
    with pytest.raises(ParameterError):
        TreeDpf2Party(0)


def test_tree_dpf_key_size_is_logarithmic():
    small = TreeDpf2Party(8).generate(1, 1)[0].key_bytes
    large = TreeDpf2Party(24).generate(1, 1)[0].key_bytes
    assert large < 3 * small  # O(n), nothing like O(sqrt(2^n))


@pytest.mark.parametrize("party_count", [2, 3, 5])
def test_naive_sharing(party_count):
    import functools
    import operator

    naive = NaiveXorSharing(6, party_count)
    alpha, beta = 17, secrets.randbits(64)
    keys = naive.generate(alpha, beta)
    assert len({k.table for k in keys}) == party_count
    for x in range(64):
        combined = functools.reduce(
            operator.xor, (naive.evaluate(k, x) for k in keys)
        )
        assert combined == (beta if x == alpha else 0)
    assert keys[0].key_bytes == 64 * 8


def test_plaintext_lookup_floor():
    lookup = PlaintextLookup(["aa", "bb", "cc"])
    assert lookup.lookup("bb") == 1
    assert lookup.lookup("zz") is None


def test_socket_transport_end_to_end(tmp_path, snapshot, ids):
    evaluator_ids = ["mp_fss_0", "mp_fss_1", "mp_fss_2"]
    replicate_opaque_snapshots_multiparty([snapshot], evaluator_ids, tmp_path)
    servers = []
    clients = []
    try:
        for evaluator_id in evaluator_ids:
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(ROOT / "multiparty_fss/tools/serve_multiparty_evaluator.py"),
                    "--store",
                    str(tmp_path / evaluator_id),
                    "--evaluator-id",
                    evaluator_id,
                    "--port",
                    "0",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=ROOT,
            )
            ready = process.stdout.readline().strip()
            assert ready.startswith("READY "), process.stderr.read()[:300]
            servers.append(process)
            clients.append(SocketEvaluatorClient("127.0.0.1", int(ready.split()[1])))

        store = MultipartyFssEvaluatorStore.load(tmp_path / "mp_fss_0")
        universe = store.universe("entity")
        alice = ids.entity_id("Alice")
        rank = universe.rank_of(alice)
        shares = generate(
            rank,
            1,
            3,
            1,
            domain_bits=universe.domain_bits,
            domain_binding=universe.digest(),
        )
        responses = []
        for index, client in enumerate(clients):
            request = MpFssEvaluatorRequest(
                request_id="sock-1",
                domain="entity",
                evaluator_id=evaluator_ids[index],
                party_index=index,
                party_count=3,
                threshold=1,
                key_share=shares[index],
                projection=None,
            )
            raw = client.evaluate(json.loads(json.dumps(request.to_dict())))
            responses.append(MpFssEvaluatorResponse.from_dict(raw))
        combined = MpFssCoordinator(3, 1).combine(responses, "sock-1")
        nonzero = {
            universe.points[i]: v for i, v in enumerate(combined.values) if v != 0
        }
        assert nonzero == {alice: 1}

        # Fail-closed over the wire: a request addressed to the wrong
        # evaluator is refused by the remote service.
        bad_request = MpFssEvaluatorRequest(
            request_id="sock-2",
            domain="entity",
            evaluator_id="mp_fss_1",
            party_index=1,
            party_count=3,
            threshold=1,
            key_share=shares[1],
            projection=None,
        )
        with pytest.raises(ResponseValidationError, match="refused"):
            clients[0].evaluate(bad_request.to_dict())
    finally:
        for process in servers:
            process.terminate()
        for process in servers:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
