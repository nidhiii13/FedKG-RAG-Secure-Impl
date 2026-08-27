"""Shared fixtures for the multi-party FSS test suite.

Run from the repository root:  .venv/bin/pytest multiparty_fss/tests
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest

from src.crypto.hmac_ids import HmacIdProvider
from src.party.opaque_index_snapshot import OpaqueIndexSnapshot
from src.party.secure_index import SecurePartyIndex


@pytest.fixture(scope="session")
def ids() -> HmacIdProvider:
    return HmacIdProvider(b"multiparty-fss-test-key")


@pytest.fixture(scope="session")
def snapshot(ids: HmacIdProvider) -> OpaqueIndexSnapshot:
    """One party's plaintext-free opaque snapshot over a small toy graph."""
    graph = {
        "Alice": {"knows": ["Bob"], "works_at": ["Acme"]},
        "Bob": {"knows": ["Carol"]},
        "Carol": {"works_at": ["Globex"]},
        "Acme": {},
        "Globex": {},
        "Dave": {"knows": ["Alice"]},
    }
    types = {"person": ["Alice", "Bob", "Carol", "Dave"], "org": ["Acme", "Globex"]}
    index = SecurePartyIndex.from_plain_graph("p0", graph, types, ids)
    return OpaqueIndexSnapshot.from_secure_index(index, ids)


@pytest.fixture(scope="session")
def second_snapshot(ids: HmacIdProvider) -> OpaqueIndexSnapshot:
    graph = {
        "Erin": {"knows": ["Frank"]},
        "Frank": {"works_at": ["Initech"]},
        "Initech": {},
    }
    types = {"person": ["Erin", "Frank"], "org": ["Initech"]}
    index = SecurePartyIndex.from_plain_graph("p1", graph, types, ids)
    return OpaqueIndexSnapshot.from_secure_index(index, ids)
