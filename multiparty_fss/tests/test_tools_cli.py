"""End-to-end CLI tests: export -> N evaluator workers -> combine, and the
in-process query tool. Exercises the role-separated process topology with
N replicated stores and configurable evaluator lists."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "multiparty_fss" / "tools"


def _run(argv, stdin_text=None, env_extra=None):
    import os

    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, *argv],
        input=stdin_text,
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=env,
        timeout=300,
    )


@pytest.fixture(scope="module")
def exported_stores(tmp_path_factory):
    """Export one snapshot to a 3-evaluator store set via the CLI."""
    from src.crypto.hmac_ids import HmacIdProvider
    from src.party.opaque_index_snapshot import OpaqueIndexSnapshot
    from src.party.secure_index import SecurePartyIndex

    tmp = tmp_path_factory.mktemp("mpfss-cli")
    ids = HmacIdProvider(b"multiparty-fss-test-key")
    index = SecurePartyIndex.from_plain_graph(
        "p0",
        {"Alice": {"knows": ["Bob"]}, "Bob": {}, "Carol": {}},
        {"person": ["Alice", "Bob", "Carol"]},
        ids,
    )
    snapshot = OpaqueIndexSnapshot.from_secure_index(index, ids)
    snapshot_path = tmp / "partition.json"
    snapshot.write(snapshot_path)

    stores_dir = tmp / "stores"
    result = _run(
        [
            str(TOOLS / "export_multiparty_snapshots.py"),
            "--snapshot",
            str(snapshot_path),
            "--evaluator",
            "mp_fss_0",
            "--evaluator",
            "mp_fss_1",
            "--evaluator",
            "mp_fss_2",
            "--output-dir",
            str(stores_dir),
        ]
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["party_count"] == 3
    assert report["threshold"] == 1
    return stores_dir, ids


def test_export_rejects_two_evaluators(tmp_path, exported_stores):
    stores_dir, _ = exported_stores
    snapshot_path = next((stores_dir / "mp_fss_0" / "partitions").glob("*.json"))
    result = _run(
        [
            str(TOOLS / "export_multiparty_snapshots.py"),
            "--snapshot",
            str(snapshot_path),
            "--evaluator",
            "a",
            "--evaluator",
            "b",
            "--output-dir",
            str(tmp_path / "bad"),
        ]
    )
    assert result.returncode != 0
    assert "legacy" in result.stderr


def test_worker_pipeline_reconstructs_via_combine(exported_stores):
    stores_dir, ids = exported_stores
    sys.path.insert(0, str(ROOT))
    from multiparty_fss.keygen import generate
    from multiparty_fss.projection import build_xor_projection
    from multiparty_fss.service import MultipartyFssEvaluatorStore
    from src.aggregation.prio3_candidates import SessionCandidateHandleProvider

    store0 = MultipartyFssEvaluatorStore.load(stores_dir / "mp_fss_0")
    universe = store0.universe("entity")
    alice = ids.entity_id("Alice")
    alpha = universe.rank_of(alice)
    assert alpha is not None
    shares = generate(
        alpha,
        1,
        3,
        1,
        domain_bits=universe.domain_bits,
        domain_binding=universe.digest(),
    )
    handles = SessionCandidateHandleProvider(b"0123456789abcdef", b"nonce-0123456789")
    built = build_xor_projection(store0.index, handles, "entity", capacity=8)
    projection_payload = built.projection.as_dict()

    responses = []
    for index in range(3):
        request = {
            "version": "fedkg-mpfss-request-v1",
            "construction": "bgi15-mpdpf-p0",
            "request_id": "cli-req-1",
            "domain": "entity",
            "evaluator_id": f"mp_fss_{index}",
            "party_index": index,
            "party_count": 3,
            "threshold": 1,
            "key_share": shares[index].to_dict(),
            "projection": projection_payload,
        }
        result = _run(
            [
                str(TOOLS / "run_multiparty_evaluator.py"),
                "--store",
                str(stores_dir / f"mp_fss_{index}"),
                "--evaluator-id",
                f"mp_fss_{index}",
            ],
            stdin_text=json.dumps(request),
        )
        assert result.returncode == 0, result.stderr
        responses.append(json.loads(result.stdout))

    combined = _run(
        [
            str(TOOLS / "combine_multiparty_shares.py"),
            "--party-count",
            "3",
            "--request-id",
            "cli-req-1",
        ],
        stdin_text=json.dumps(responses),
    )
    assert combined.returncode == 0, combined.stderr
    output = json.loads(combined.stdout)
    nonzero = output["nonzero_candidate_slots"]
    assert list(nonzero.values()) == [1]
    (handle,) = nonzero
    assert built.handle_to_candidate_id[handle] == alice

    # Fail-closed: dropping one response must be refused, not "combined anyway".
    partial = _run(
        [
            str(TOOLS / "combine_multiparty_shares.py"),
            "--party-count",
            "3",
        ],
        stdin_text=json.dumps(responses[:2]),
    )
    assert partial.returncode != 0
    assert "exactly 3" in partial.stderr

    # Fail-closed: a duplicated response must be refused.
    duplicated = _run(
        [
            str(TOOLS / "combine_multiparty_shares.py"),
            "--party-count",
            "3",
        ],
        stdin_text=json.dumps([responses[0], responses[1], responses[1]]),
    )
    assert duplicated.returncode != 0

    # Fail-closed: the worker refuses a request addressed to another evaluator.
    misaddressed = dict(request)
    result = _run(
        [
            str(TOOLS / "run_multiparty_evaluator.py"),
            "--store",
            str(stores_dir / "mp_fss_0"),
            "--evaluator-id",
            "mp_fss_0",
        ],
        stdin_text=json.dumps(misaddressed),
    )
    assert result.returncode != 0  # request was built for party 2


def test_query_tool_end_to_end(exported_stores):
    stores_dir, ids = exported_stores
    result = _run(
        [
            str(TOOLS / "run_multiparty_fss_query.py"),
            "--store",
            str(stores_dir / "mp_fss_0"),
            "--store",
            str(stores_dir / "mp_fss_1"),
            "--store",
            str(stores_dir / "mp_fss_2"),
            "--party-count",
            "3",
            "--threshold",
            "1",
            "--domain",
            "entity",
            "--alpha",
            ids.entity_id("Bob"),
            "--request-id",
            "cli-q-1",
            "--query-nonce",
            "nonce-0123456789",
            "--capacity",
            "8",
        ],
        env_extra={"FEDKG_PRIO_HANDLE_KEY": "0123456789abcdef"},
    )
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output["party_count"] == 3
    assert output["threshold"] == 1
    assert output["construction"] == "bgi15-mpdpf-p0"
    assert output["output_group"] == "xor64"
    assert list(output["candidate_values"].values()) == [1]
    assert list(output["candidate_values"]) == [ids.entity_id("Bob")]


def test_query_tool_rejects_incomplete_store_set(exported_stores):
    stores_dir, ids = exported_stores
    result = _run(
        [
            str(TOOLS / "run_multiparty_fss_query.py"),
            "--store",
            str(stores_dir / "mp_fss_0"),
            "--store",
            str(stores_dir / "mp_fss_1"),
            "--domain",
            "entity",
            "--alpha",
            ids.entity_id("Bob"),
            "--request-id",
            "cli-q-2",
            "--query-nonce",
            "nonce-0123456789",
            "--capacity",
            "8",
        ],
        env_extra={"FEDKG_PRIO_HANDLE_KEY": "0123456789abcdef"},
    )
    assert result.returncode != 0
    assert "complete N-party evaluator set" in result.stderr
