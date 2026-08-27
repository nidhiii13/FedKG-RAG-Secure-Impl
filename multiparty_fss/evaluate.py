"""Evaluation: BGI15 Algorithm 4, Eval^{p0}(i, k_i, x).

Party i's output share for input x = (gamma', delta') is block delta' of

    y_i = XOR over { j : s_{gamma',j} != 0 } of ( cw_j XOR G(s_{gamma',j}) )

(Algorithm 4 lines 6-7). The heavy work is per-row, not per-point, so batch
evaluation groups points by row and computes each row vector once; scalar and
batch evaluation are bit-identical by construction (and tested to be).

Output shares are Python ints in [0, 2^64) representing elements of GF(2)^64.
They combine by XOR (multiparty_fss/combine.py) — never by modular addition.
"""

from __future__ import annotations

from typing import Iterable, Sequence

import numpy as np

from multiparty_fss.errors import ParameterError
from multiparty_fss.keyshare import MpDpfKeyShare
from multiparty_fss.prg import expand_seed


def _row_vector(key_share: MpDpfKeyShare, row: int) -> np.ndarray:
    """y_i for one row gamma': a length-mu uint64 vector."""
    params = key_share.params
    seeds = key_share.seed_blocks()
    cw = key_share.cw_matrix()
    accumulator = np.zeros(params.mu, dtype="<u8")
    for j in range(params.seeds_per_row):
        block = seeds[row, j]
        if not block.any():  # all-zero block: seed not held (paper sentinel)
            continue
        accumulator ^= cw[j]
        accumulator ^= expand_seed(params, block.tobytes())
    return accumulator


def evaluate(key_share: MpDpfKeyShare, point: int) -> int:
    """Eval^{p0} at a single domain point; returns this party's output share."""
    gamma, delta = key_share.params.cell(point)
    return int(_row_vector(key_share, gamma)[delta])


def evaluate_many(key_share: MpDpfKeyShare, points: Sequence[int]) -> list[int]:
    """Eval^{p0} over a batch of points, amortizing per-row PRG expansion.

    Returns output shares aligned with `points`. Equivalent to
    [evaluate(key_share, x) for x in points].
    """
    params = key_share.params
    point_list = list(points)
    for x in point_list:
        if not isinstance(x, int) or isinstance(x, bool):
            raise ParameterError("evaluation points must be integers")
        if not 0 <= x < params.domain_size:
            raise ParameterError("evaluation point out of the input domain")
    rows_needed = sorted({x // params.mu for x in point_list})
    row_cache = {row: _row_vector(key_share, row) for row in rows_needed}
    return [int(row_cache[x // params.mu][x % params.mu]) for x in point_list]


def evaluate_universe(key_share: MpDpfKeyShare, universe_size: int) -> np.ndarray:
    """Output shares for every rank 0..universe_size-1 as a uint64 vector.

    This is the evaluator-service fast path (full shared-universe sweep).
    """
    params = key_share.params
    if not 0 < universe_size <= params.domain_size:
        raise ParameterError("universe size out of the input domain")
    last_row = (universe_size - 1) // params.mu
    parts: list[np.ndarray] = []
    for row in range(last_row + 1):
        parts.append(_row_vector(key_share, row))
    flat = np.concatenate(parts)
    return flat[:universe_size].copy()


def output_shares_equal(scalar: Iterable[int], batch: Iterable[int]) -> bool:
    """Helper used by tests to assert scalar/batch equivalence."""
    return list(scalar) == list(batch)
