"""Correctness of Gen^{p0}/Eval^{p0} against the paper's correctness equation.

    XOR_{i=0}^{N-1} Eval(i, k_i, x) = beta  if x = alpha
                                    = 0     otherwise

Passing these tests establishes FUNCTIONAL behavior only. It is not evidence
of cryptographic privacy (see multiparty_fss/SECURITY.md).

An independent brute-force cross-check model (`_model_combined`) recomputes
the combined evaluation directly from the paper's algebra — expanding every
row's seeds with per-party holding sets reconstructed from the key shares —
and must agree with the production Eval path. No official external test
vectors exist for this construction (no public implementation; see
docs/multiparty_fss/research_and_design.md section 1.3).
"""

from __future__ import annotations

import secrets

import pytest

from multiparty_fss.combine import combine, combine_vectors
from multiparty_fss.evaluate import evaluate, evaluate_many, evaluate_universe
from multiparty_fss.keygen import generate
from multiparty_fss.params import MpDpfParams
from multiparty_fss.prg import expand_seed

REQUIRED_CONFIGS = [(3, 1), (4, 1), (5, 2), (7, 3)]
BETA_MAX = (1 << 64) - 1


def _combine_at(shares, x, party_count):
    return combine({s.party_index: evaluate(s, x) for s in shares}, party_count)


def _model_combined(shares, x):
    """Independent recomputation of XOR_i Eval(i, k_i, x) from raw key bytes.

    Walks every party's sigma blocks for row gamma' and XORs cw_j + G(s) for
    each held seed, without going through evaluate()'s row cache — a second
    implementation of Algorithm 4 used as a cross-check oracle.
    """
    params = shares[0].params
    gamma, delta = params.cell(x)
    total = 0
    for share in shares:
        seeds = share.seed_blocks()
        cw = share.cw_matrix()
        for j in range(params.seeds_per_row):
            block = seeds[gamma, j]
            if not block.any():
                continue
            total ^= int(cw[j][delta]) ^ int(expand_seed(params, block.tobytes())[delta])
    return total


@pytest.mark.parametrize("party_count,threshold", REQUIRED_CONFIGS)
def test_alpha_hit_reconstructs_beta_and_all_other_points_zero(party_count, threshold):
    params = MpDpfParams.create(7, party_count, threshold)
    alpha, beta = 77, 0xA5A5_5A5A_DEAD_BEEF
    shares = generate(alpha, beta, party_count, threshold, params=params)
    assert len(shares) == party_count
    assert _combine_at(shares, alpha, party_count) == beta
    for x in range(params.domain_size):  # every point in the full domain
        expected = beta if x == alpha else 0
        assert _combine_at(shares, x, party_count) == expected


@pytest.mark.parametrize("party_count,threshold", REQUIRED_CONFIGS)
@pytest.mark.parametrize("beta", [0, 1, BETA_MAX])
def test_beta_edge_values(party_count, threshold, beta):
    params = MpDpfParams.create(6, party_count, threshold)
    alpha = 33
    shares = generate(alpha, beta, party_count, threshold, params=params)
    assert _combine_at(shares, alpha, party_count) == beta
    for x in (0, 1, 32, 34, params.domain_size - 1):
        assert _combine_at(shares, x, party_count) == (beta if x == alpha else 0)


@pytest.mark.parametrize("party_count,threshold", REQUIRED_CONFIGS)
def test_boundary_alphas(party_count, threshold):
    params = MpDpfParams.create(6, party_count, threshold)
    domain = params.domain_size
    # Boundary alphas: first/last point, and the row-boundary points when the
    # grid has more than one row (mu can equal 2^n for large p, small n).
    alphas = {0, 1, domain - 1}
    if params.mu < domain:
        alphas.update({params.mu - 1, params.mu})
    for alpha in sorted(alphas):
        shares = generate(alpha, 1, party_count, threshold, params=params)
        assert _combine_at(shares, alpha, party_count) == 1
        for x in {0, min(params.mu, domain - 1), domain - 1}:
            if x != alpha:
                assert _combine_at(shares, x, party_count) == 0


@pytest.mark.parametrize("party_count,threshold", REQUIRED_CONFIGS)
def test_randomized_property_full_domain(party_count, threshold):
    params = MpDpfParams.create(5, party_count, threshold)
    for _ in range(5):  # repeated randomized trials
        alpha = secrets.randbelow(params.domain_size)
        beta = secrets.randbits(64)
        shares = generate(alpha, beta, party_count, threshold, params=params)
        per_party = [evaluate_many(s, list(range(params.domain_size))) for s in shares]
        for x in range(params.domain_size):
            combined = 0
            for vector in per_party:
                combined ^= vector[x]
            assert combined == (beta if x == alpha else 0)


@pytest.mark.parametrize("party_count,threshold", REQUIRED_CONFIGS)
def test_scalar_batch_and_universe_evaluation_agree(party_count, threshold):
    params = MpDpfParams.create(8, party_count, threshold)
    alpha = 200
    shares = generate(alpha, 99, party_count, threshold, params=params)
    points = [0, 1, 7, alpha, 201, params.domain_size - 1, alpha, 3]
    for share in shares:
        scalar = [evaluate(share, x) for x in points]
        batch = evaluate_many(share, points)
        assert scalar == batch
        sweep = evaluate_universe(share, params.domain_size)
        assert [int(sweep[x]) for x in points] == scalar


@pytest.mark.parametrize("party_count,threshold", REQUIRED_CONFIGS)
def test_independent_bruteforce_model_agrees(party_count, threshold):
    params = MpDpfParams.create(6, party_count, threshold)
    alpha = secrets.randbelow(params.domain_size)
    beta = secrets.randbits(64)
    shares = generate(alpha, beta, party_count, threshold, params=params)
    for x in range(params.domain_size):
        assert _model_combined(shares, x) == _combine_at(shares, x, party_count)


def test_additional_party_count_eight():
    # A larger practical N beyond the required set.
    params = MpDpfParams.create(6, 8)  # default t = 3
    assert params.threshold == 3
    shares = generate(17, 5, 8, params=params)
    assert _combine_at(shares, 17, 8) == 5
    assert _combine_at(shares, 16, 8) == 0


@pytest.mark.parametrize("party_count,threshold", REQUIRED_CONFIGS)
def test_combine_vectors_matches_pointwise_combine(party_count, threshold):
    params = MpDpfParams.create(5, party_count, threshold)
    shares = generate(11, 4242, party_count, threshold, params=params)
    vectors = {
        s.party_index: evaluate_many(s, list(range(params.domain_size))) for s in shares
    }
    combined = combine_vectors(vectors, party_count)
    for x in range(params.domain_size):
        assert combined[x] == _combine_at(shares, x, party_count)


@pytest.mark.parametrize("party_count,threshold", REQUIRED_CONFIGS)
def test_each_party_gets_a_distinct_key_share(party_count, threshold):
    params = MpDpfParams.create(5, party_count, threshold)
    shares = generate(3, 1, party_count, threshold, params=params)
    assert sorted(s.party_index for s in shares) == list(range(party_count))
    sigmas = {s.sigma for s in shares}
    assert len(sigmas) == party_count  # no duplicated evaluator key material
    # Correction words are common to all keys BY CONSTRUCTION (Algorithm 3
    # line 9 concatenates the same cw_1..cw_S into every k_i).
    assert len({s.correction_words for s in shares}) == 1
    keygen_ids = {s.keygen_id for s in shares}
    assert len(keygen_ids) == 1


def test_fresh_randomness_across_generations():
    params = MpDpfParams.create(5, 3, 1)
    first = generate(4, 1, 3, 1, params=params)
    second = generate(4, 1, 3, 1, params=params)
    assert first[0].keygen_id != second[0].keygen_id
    assert first[0].sigma != second[0].sigma
    assert first[0].correction_words != second[0].correction_words
