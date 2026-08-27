"""Sampling of the parity arrays E_p / O_p (BGI15 Notation 2).

E_p (resp. O_p) is the set of binary p x 2^{p-1} arrays whose columns are ALL
the p-bit strings with an even (resp. odd) number of 1 bits, each appearing
exactly once. Sampling A uniformly from E_p / O_p therefore means applying a
uniformly random permutation to the fixed set of even/odd-parity columns.

Encoding convention (documented; see paper_to_code_mapping.md): a column is a
p-bit integer c, and party i (0-based) holds seed j iff bit i of column j's
integer is 1.

Properties relied on by the scheme (both are consequences of the enumeration,
not extra assumptions):
- every column of an E_p array has even Hamming weight, so each seed of a
  non-special row is held by an even number of parties (possibly zero: the
  all-zero column) and cancels under XOR across all p evaluations;
- every column of an O_p array has odd weight, so each seed of the special row
  survives once; in particular the p weight-1 columns e_i give every party
  exactly one exclusively-held seed, which is what masks the correction-word
  constraint against any coalition of p-1 parties (BGI15 Section 3.1,
  properties 1-2 and the secrecy argument).

Randomness: secrets.SystemRandom (OS CSPRNG), per the repository-wide rule
that no key-material randomness may come from a deterministic PRNG.
"""

from __future__ import annotations

import secrets
from functools import lru_cache

from multiparty_fss.errors import ParameterError

_SYSTEM_RANDOM = secrets.SystemRandom()


@lru_cache(maxsize=32)
def parity_columns(party_count: int, odd: bool) -> tuple[int, ...]:
    """All p-bit integers with odd/even Hamming weight, ascending (2^{p-1} of them)."""
    if party_count < 1:
        raise ParameterError("party_count must be positive")
    want = 1 if odd else 0
    return tuple(
        column
        for column in range(1 << party_count)
        if bin(column).count("1") % 2 == want
    )


def sample_parity_array(party_count: int, odd: bool) -> list[int]:
    """A uniform element of O_p (odd=True) or E_p (odd=False), as a list of
    2^{p-1} column integers; index j is column j of the array."""
    columns = list(parity_columns(party_count, odd))
    _SYSTEM_RANDOM.shuffle(columns)
    return columns


def party_holds(column: int, party_index: int) -> bool:
    """A[i, j] for column integer `column` and 0-based party i."""
    return bool((column >> party_index) & 1)
