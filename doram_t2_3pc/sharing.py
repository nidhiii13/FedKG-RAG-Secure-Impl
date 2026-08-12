from __future__ import annotations

import secrets
from collections.abc import Iterable

from .config import FIELD_PRIME


SERVER_COUNT = 3


def share(value: int, *, modulus: int = FIELD_PRIME) -> tuple[int, int, int]:
    """Return a perfect 3-out-of-3 additive sharing over ``modulus``."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("shared values must be integers, not booleans or floats")
    if not 0 <= value < modulus:
        raise ValueError(f"value must be in [0, {modulus})")
    first = secrets.randbelow(modulus)
    second = secrets.randbelow(modulus)
    third = (value - first - second) % modulus
    return first, second, third


def share_vector(
    values: Iterable[int], *, modulus: int = FIELD_PRIME
) -> tuple[list[int], list[int], list[int]]:
    outputs = ([], [], [])
    for value in values:
        pieces = share(value, modulus=modulus)
        for server in range(SERVER_COUNT):
            outputs[server].append(pieces[server])
    return outputs


def reconstruct(pieces: Iterable[int], *, modulus: int = FIELD_PRIME) -> int:
    pieces = tuple(pieces)
    if len(pieces) != SERVER_COUNT:
        raise ValueError(f"expected exactly {SERVER_COUNT} shares")
    if any(isinstance(x, bool) or not isinstance(x, int) or not 0 <= x < modulus for x in pieces):
        raise ValueError("shares must be canonical field elements")
    return sum(pieces) % modulus
