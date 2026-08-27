"""Parameter validation, threshold arithmetic, and grid-dimension tests."""

from __future__ import annotations

import pytest

from multiparty_fss.errors import ParameterError
from multiparty_fss.params import (
    MAX_PARTIES,
    MIN_PARTIES,
    MpDpfParams,
    domain_bits_for_universe,
    honest_majority_threshold,
)


def test_honest_majority_threshold_table():
    # The mandated t = floor((N - 1) / 2) examples from the task.
    assert honest_majority_threshold(3) == 1
    assert honest_majority_threshold(4) == 1
    assert honest_majority_threshold(5) == 2
    assert honest_majority_threshold(7) == 3
    assert honest_majority_threshold(8) == 3
    assert honest_majority_threshold(10) == 4


@pytest.mark.parametrize("party_count", range(MIN_PARTIES, MAX_PARTIES + 1))
def test_default_threshold_is_honest_majority(party_count):
    params = MpDpfParams.create(domain_bits=8, party_count=party_count)
    assert params.threshold == (party_count - 1) // 2
    # Honest majority: strictly more than half of the parties stay honest.
    assert party_count - params.threshold > party_count / 2


@pytest.mark.parametrize("party_count", range(MIN_PARTIES, MAX_PARTIES + 1))
def test_grid_dimensions_cover_domain(party_count):
    for domain_bits in (1, 2, 5, 8, 13, 17):
        params = MpDpfParams.create(domain_bits, party_count)
        # Algorithm 3 line 2: mu = ceil(sqrt(2^{n+p-1})), nu = ceil(2^n / mu).
        assert (params.mu - 1) ** 2 < (1 << (domain_bits + party_count - 1))
        assert params.mu**2 >= (1 << (domain_bits + party_count - 1))
        assert params.mu * params.nu >= params.domain_size
        assert params.seeds_per_row == 1 << (party_count - 1)


def test_rejects_two_parties_on_multiparty_path():
    with pytest.raises(ParameterError, match="legacy two-party"):
        MpDpfParams.create(domain_bits=8, party_count=2)


def test_rejects_party_count_extremes():
    with pytest.raises(ParameterError):
        MpDpfParams.create(domain_bits=8, party_count=1)
    with pytest.raises(ParameterError):
        MpDpfParams.create(domain_bits=8, party_count=MAX_PARTIES + 1)
    with pytest.raises(ParameterError):
        MpDpfParams.create(domain_bits=8, party_count=0)
    with pytest.raises(ParameterError):
        MpDpfParams.create(domain_bits=8, party_count=-3)


@pytest.mark.parametrize(
    "party_count,bad_threshold",
    [(3, 0), (3, 3), (3, -1), (5, 5), (5, 0), (7, 7), (7, 9), (4, 4)],
)
def test_rejects_invalid_thresholds(party_count, bad_threshold):
    with pytest.raises(ParameterError, match="threshold"):
        MpDpfParams.create(8, party_count, bad_threshold)


@pytest.mark.parametrize(
    "party_count,threshold", [(3, 1), (3, 2), (4, 1), (4, 3), (5, 2), (5, 4), (7, 3), (7, 6)]
)
def test_accepts_thresholds_within_construction_coverage(party_count, threshold):
    # The construction is (N-1)-secure, so any 1 <= t <= N-1 is a valid claim;
    # the deployment default remains floor((N-1)/2).
    params = MpDpfParams.create(8, party_count, threshold)
    assert params.threshold == threshold


def test_rejects_domain_bit_extremes():
    with pytest.raises(ParameterError):
        MpDpfParams.create(0, 3)
    with pytest.raises(ParameterError):
        MpDpfParams.create(31, 3)
    with pytest.raises(ParameterError):
        MpDpfParams.create(-1, 3)


def test_rejects_non_integer_parameters():
    with pytest.raises(ParameterError):
        MpDpfParams.create(8, True)  # bool masquerading as int
    with pytest.raises(ParameterError):
        MpDpfParams(domain_bits=8.0, party_count=3, threshold=1)  # type: ignore[arg-type]


def test_domain_bits_for_universe():
    assert domain_bits_for_universe(1) == 1
    assert domain_bits_for_universe(2) == 1
    assert domain_bits_for_universe(3) == 2
    assert domain_bits_for_universe(4) == 2
    assert domain_bits_for_universe(5) == 3
    assert domain_bits_for_universe(1 << 20) == 20
    with pytest.raises(ParameterError):
        domain_bits_for_universe(0)
    with pytest.raises(ParameterError):
        domain_bits_for_universe((1 << 30) + 1)


def test_params_id_binds_all_parameters():
    base = MpDpfParams.create(8, 3).params_id()
    assert MpDpfParams.create(8, 3).params_id() == base  # deterministic
    assert MpDpfParams.create(9, 3).params_id() != base
    assert MpDpfParams.create(8, 4).params_id() != base
    assert MpDpfParams.create(8, 3, threshold=2).params_id() != base


def test_cell_mapping_row_major():
    params = MpDpfParams.create(6, 3)
    assert params.cell(0) == (0, 0)
    gamma, delta = params.cell(params.domain_size - 1)
    assert gamma * params.mu + delta == params.domain_size - 1
    with pytest.raises(ParameterError):
        params.cell(params.domain_size)
    with pytest.raises(ParameterError):
        params.cell(-1)
