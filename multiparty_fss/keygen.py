"""Key generation: BGI15 Algorithm 3, Gen^{p0}(1^lambda, a, b).

Paper-to-code mapping: multiparty_fss/docs/paper_to_code_mapping.md.
Indices are 0-based here; the paper is 1-based.

Randomness: all key material (seeds, correction words, parity-array
permutations, keygen_id) comes from the OS CSPRNG (secrets). There is no
deterministic mode in this module; deterministic vectors used by tests are
constructed only inside the test suite, from explicitly labeled fixtures.

Deviation from the paper (documented in research_and_design.md section 6.2):
Algorithm 4 line 6 treats an all-zero lambda-bit block in sigma_i as "seed not
held". A uniformly drawn seed is 0^128 with probability 2^-128, which would
make a held seed unreadable. Gen therefore resamples zero seeds, making the
sentinel unambiguous. Statistical distance from the paper's distribution is at
most nu * 2^{p-1} * 2^-128 per key generation (negligible); the paper instead
carries the same quantity as a correctness error.
"""

from __future__ import annotations

import secrets

import numpy as np

from multiparty_fss.errors import ParameterError
from multiparty_fss.keyshare import DOMAIN_BINDING_RAW, MpDpfKeyShare
from multiparty_fss.params import OUTPUT_BITS, SEED_BYTES, MpDpfParams
from multiparty_fss.parity import party_holds, sample_parity_array
from multiparty_fss.prg import expand_seed

_WORD_BYTES = OUTPUT_BITS // 8


def _random_seed() -> bytes:
    while True:
        seed = secrets.token_bytes(SEED_BYTES)
        if any(seed):
            return seed


def generate(
    alpha: int,
    beta: int,
    party_count: int,
    threshold: int | None = None,
    params: MpDpfParams | None = None,
    *,
    domain_bits: int | None = None,
    domain_binding: str = DOMAIN_BINDING_RAW,
) -> list[MpDpfKeyShare]:
    """Gen^{p0}: split f_{alpha,beta} into `party_count` key shares.

    Exactly one of `params` or `domain_bits` must be provided. When `params`
    is given, `party_count`/`threshold` must match it (fail-closed against
    inconsistent call sites). Returns key shares ordered by party index; the
    caller MUST deliver share i to evaluator i only.
    """
    if params is None:
        if domain_bits is None:
            raise ParameterError("either params or domain_bits is required")
        params = MpDpfParams.create(domain_bits, party_count, threshold)
    else:
        if domain_bits is not None and domain_bits != params.domain_bits:
            raise ParameterError("domain_bits conflicts with params")
        if party_count != params.party_count:
            raise ParameterError("party_count conflicts with params")
        if threshold is not None and threshold != params.threshold:
            raise ParameterError("threshold conflicts with params")

    if not isinstance(alpha, int) or isinstance(alpha, bool):
        raise ParameterError("alpha must be an integer domain point")
    if not 0 <= alpha < params.domain_size:
        raise ParameterError("alpha out of the input domain [0, 2^n)")
    if not isinstance(beta, int) or isinstance(beta, bool):
        raise ParameterError("beta must be an integer")
    if not 0 <= beta < (1 << OUTPUT_BITS):
        raise ParameterError("beta must be a 64-bit unsigned value")

    p = params.party_count
    seeds_per_row = params.seeds_per_row
    mu, nu = params.mu, params.nu

    # Line 3: regard a as the pair (gamma, delta), row-major.
    gamma, delta = params.cell(alpha)

    # Line 4: A_gamma in O_p; A_{gamma'} in E_p for gamma' != gamma.
    arrays = [sample_parity_array(p, odd=(row == gamma)) for row in range(nu)]

    # Line 5: nu * 2^{p-1} independent uniform seeds (nonzero; see module doc).
    seeds = [[_random_seed() for _ in range(seeds_per_row)] for _ in range(nu)]

    # Line 6: cw_1..cw_S uniform subject to
    #   XOR_j (cw_j ^ G(s_{gamma,j})) = e_delta * beta.
    # Sample S-1 words uniformly and solve for the last one.
    target = np.zeros(mu, dtype="<u8")
    target[delta] = np.uint64(beta)
    prg_special = np.zeros(mu, dtype="<u8")
    for j in range(seeds_per_row):
        prg_special ^= expand_seed(params, seeds[gamma][j])

    cw = np.empty((seeds_per_row, mu), dtype="<u8")
    for j in range(seeds_per_row - 1):
        cw[j] = np.frombuffer(secrets.token_bytes(mu * _WORD_BYTES), dtype="<u8")
    partial = np.zeros(mu, dtype="<u8")
    for j in range(seeds_per_row - 1):
        partial ^= cw[j]
    cw[seeds_per_row - 1] = target ^ prg_special ^ partial
    cw_bytes = cw.tobytes()

    # Lines 7-9: sigma_{i,gamma'} blocks (seed if held, 0^lambda otherwise),
    # concatenated over rows; k_i = sigma_i || cw_1..cw_S.
    keygen_id = secrets.token_hex(16)
    zero_block = bytes(SEED_BYTES)
    shares: list[MpDpfKeyShare] = []
    for i in range(p):
        blocks: list[bytes] = []
        for row in range(nu):
            columns = arrays[row]
            for j in range(seeds_per_row):
                blocks.append(seeds[row][j] if party_holds(columns[j], i) else zero_block)
        shares.append(
            MpDpfKeyShare(
                params=params,
                party_index=i,
                keygen_id=keygen_id,
                domain_binding=domain_binding,
                sigma=b"".join(blocks),
                correction_words=cw_bytes,
            )
        )
    return shares
