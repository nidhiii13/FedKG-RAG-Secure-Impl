from __future__ import annotations

import random

import pytest

from doram_t2_3pc.oram_access import (
    OramAccessShape,
    assemble_oram_inputs,
    decode_oram_access_logs,
    flatten_owner_stack,
    share_access_addresses,
    share_owner_stack,
)
from doram_t2_3pc.oram_access_program import program_name, render_program
from doram_t2_3pc.oram_layout import build_owner_oram_stack
from doram_t2_3pc.sharing import reconstruct


PRIME = 2**127 - 1


def _fixture(*, chi: int = 4, accesses: int = 4):
    values = [[1000 + index, 2000 + index] for index in range(128)]
    stack = build_owner_oram_stack(
        values,
        chi=chi,
        base_threshold=8,
        rng=random.Random(17),
    )
    shape = OramAccessShape.from_stack(stack, max_accesses=accesses)
    return values, stack, shape


def test_shape_counts_exact_flattened_input():
    _, stack, shape = _fixture()
    assert shape.owner_values == len(flatten_owner_stack(stack))
    assert shape.value_width == 2
    assert shape.client_values == 4
    assert shape.total_values_per_server == shape.owner_values + 4


def test_owner_and_client_prepare_independently_then_assemble():
    _, stack, shape = _fixture()
    owner = share_owner_stack(stack, max_accesses=4, modulus=PRIME)
    addresses = [7, 19, 7, 100]
    client = share_access_addresses(addresses, shape=shape, modulus=PRIME)
    combined = assemble_oram_inputs(owner, client)

    assert all(len(shard) == shape.total_values_per_server for shard in combined.server_values)
    owner_plain = flatten_owner_stack(stack)
    for index, expected in enumerate(owner_plain + addresses):
        assert reconstruct(
            [combined.server_values[server][index] for server in range(3)],
            modulus=PRIME,
        ) == expected


def test_query_preparer_fails_closed_on_shape_or_range_mismatch():
    _, _, shape = _fixture()
    with pytest.raises(ValueError, match="exactly 4"):
        share_access_addresses([1], shape=shape, modulus=PRIME)
    with pytest.raises(ValueError, match="outside"):
        share_access_addresses([1, 2, 3, 128], shape=shape, modulus=PRIME)
    with pytest.raises(TypeError, match="integers"):
        share_access_addresses([1, 2, 3, True], shape=shape, modulus=PRIME)


def test_circuit_rejects_non_power_of_two_packing_factor():
    values = [[index] for index in range(64)]
    stack = build_owner_oram_stack(
        values, chi=3, base_threshold=8, rng=random.Random(4)
    )
    with pytest.raises(ValueError, match="power-of-two"):
        OramAccessShape.from_stack(stack, max_accesses=2)


def test_rendered_circuit_contains_recursive_stashes_and_client_only_output():
    _, _, shape = _fixture()
    source = render_program(shape)
    assert "dummy_leaf = sint.get_random_int" in source
    assert "opened_leaf = stash_hit.if_else(dummy_leaf, real_leaf).reveal()" in source
    assert "position_base = shared_array(BASE_ENTRIES)" in source
    assert "requested = shared_array(MAX_ACCESSES)" in source
    assert "ORAM_ACCESS_SHARE" in source
    assert "reveal_to(0)" in source and "reveal_to(1)" in source and "reveal_to(2)" in source
    for level in range(len(shape.levels)):
        assert f"def access_level_{level}" in source
        assert f"stash_{level}_values" in source


def test_program_identity_binds_every_public_shape_parameter():
    _, _, four = _fixture(accesses=4)
    _, _, five = _fixture(accesses=5)
    assert program_name(four) != program_name(five)


def test_client_decoder_requires_complete_role_separated_logs(tmp_path):
    _, _, shape = _fixture(accesses=1)
    values = (1, 1007, 2007)
    shares_by_field = [
        (17, 23, (value - 40) % PRIME) for value in values
    ]
    logs = []
    for server in range(3):
        path = tmp_path / f"server-{server}.log"
        path.write_text(
            "".join(
                f"ORAM_ACCESS_SHARE 0 {field} {server} {pieces[server]}\n"
                for field, pieces in enumerate(shares_by_field)
            ),
            encoding="utf-8",
        )
        logs.append(path)
    assert decode_oram_access_logs(logs, shape=shape, modulus=PRIME) == [
        {"found": 1, "values": [1007, 2007]}
    ]
    with pytest.raises(ValueError, match="exactly three"):
        decode_oram_access_logs(logs[:2], shape=shape, modulus=PRIME)
