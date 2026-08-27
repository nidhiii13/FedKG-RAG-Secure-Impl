"""Output-share combination for the BGI15 p-party DPF.

The output decoder is the p-party additive decoder over GF(2)^64 (BGI15
Definition 1 with the group operator XOR):

    Combine(y_0, ..., y_{N-1}) = y_0 XOR y_1 XOR ... XOR y_{N-1}

Correctness (BGI15 Section 3.1):  = beta if x = alpha, 0 otherwise.

All N shares are required; there is no threshold reconstruction and no
tolerance for missing parties (availability is documented separately from
privacy — SECURITY.md). Correct reconstruction is a functionality statement
only and is never treated as evidence of privacy.

This module combines *raw* output shares indexed by party. Combination of
evaluator *responses* (with request/universe/projection binding) lives in
multiparty_fss/requests.py, which layers the full validation matrix on top.
"""

from __future__ import annotations

from typing import Mapping, Sequence

from multiparty_fss.errors import CombineError
from multiparty_fss.params import OUTPUT_BITS

_WORD_MASK = (1 << OUTPUT_BITS) - 1


def _check_share_value(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise CombineError("output shares must be integers")
    if not 0 <= value <= _WORD_MASK:
        raise CombineError("output share out of the 64-bit output group")
    return value


def combine(
    output_shares: Mapping[int, int],
    party_count: int,
) -> int:
    """XOR-combine one output share per party for a single evaluation point.

    `output_shares` maps party index -> share. Exactly the indices
    0..party_count-1 must be present (missing, duplicate — impossible in a
    dict but guarded via index range — or extra indices are refused).
    """
    if not isinstance(party_count, int) or isinstance(party_count, bool):
        raise CombineError("party_count must be an integer")
    expected = set(range(party_count))
    provided = set(output_shares)
    if provided != expected:
        missing = sorted(expected - provided)
        unexpected = sorted(provided - expected)
        raise CombineError(
            f"combine requires exactly one share per party index; "
            f"missing={missing} unexpected={unexpected}"
        )
    result = 0
    for index in range(party_count):
        result ^= _check_share_value(output_shares[index])
    return result


def combine_vectors(
    share_vectors: Mapping[int, Sequence[int]],
    party_count: int,
) -> list[int]:
    """XOR-combine per-party share vectors of equal length, element-wise."""
    expected = set(range(party_count))
    if set(share_vectors) != expected:
        missing = sorted(expected - set(share_vectors))
        unexpected = sorted(set(share_vectors) - expected)
        raise CombineError(
            f"combine requires exactly one share vector per party index; "
            f"missing={missing} unexpected={unexpected}"
        )
    lengths = {len(vector) for vector in share_vectors.values()}
    if len(lengths) != 1:
        raise CombineError("share vectors must all have the same length")
    (length,) = lengths
    combined = [0] * length
    for index in range(party_count):
        vector = share_vectors[index]
        for position in range(length):
            combined[position] ^= _check_share_value(vector[position])
    return combined
