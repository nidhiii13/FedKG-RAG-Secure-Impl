"""One-time MPC verification of the federation-wide ``global_frontier`` bound.

Why this exists
---------------
``frontier_per_owner`` is enforced by each owner against its own data, alone and
fail-closed, before any share is produced. ``global_frontier`` cannot be: it
bounds a per-key edge count summed across *all* owners, and no owner can see
that sum. Until this check runs, a layout declaring ``global_frontier`` rests on
an unverified assumption -- and an understated bound does not fail closed, it
silently drops matches at the second hop.

Why it is cheap
---------------
The retrieval circuit is expensive because it must hide *which* key it reads, so
every access is a full oblivious scan. This check has no such requirement: it
verifies **every** key, so the row index is public at every step. There is no
demux, no one-hot selector, and no oblivious indexing anywhere. On the bounded
honest-input domain, a public interpolation polynomial evaluates the overflow
predicate exactly using a small fixed number of SIMD field multiplications per
row and no bit decomposition. It is paid once at preparation, not per query.

Every owner writes its per-key count at the same bit position, so the servers'
additive reconstruction of the shares is already the federation-wide count. The
circuit never has to unpack or combine anything.

What it opens
-------------
Exactly one value: the number of keys exceeding the bound. That is a fact about
whether the declared ``global_frontier`` holds, which is what declaring it
already asserts publicly. No per-key count, no owner's contribution, and no key
identity is revealed. A non-zero result means the layout must be rejected; it
deliberately does not say *which* keys overflowed, because that would leak the
degree distribution the bound exists to summarize.

Threat model is unchanged: three servers, static passive adversary corrupting any
two, 3-of-3 additive sharing, no dealer.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from .config import SCALABLE_FIELD_PRIMES
from .relation_pages import RelationPageConfig


BOUND_CHECK_VERSION = 3


def overflow_polynomial(bound: int, maximum: int, prime: int) -> tuple[int, ...]:
    """Interpolate ``1[x > bound]`` on the promised count domain.

    Owner preparation guarantees that the reconstructed occupancy is in
    ``0..maximum`` in the passive-input model.  Evaluating this public
    polynomial therefore gives exactly the same bit as an integer comparison,
    while avoiding a full-width bit decomposition for every directory row.
    Coefficients are returned in ascending degree order modulo ``prime``.
    """

    if not 0 <= bound < maximum < prime:
        raise ValueError("invalid overflow-polynomial domain")
    result = [0] * (maximum + 1)
    for point in range(bound + 1, maximum + 1):
        basis = [1]
        denominator = 1
        for other in range(maximum + 1):
            if other == point:
                continue
            product = [0] * (len(basis) + 1)
            for degree, coefficient in enumerate(basis):
                product[degree] = (
                    product[degree] - other * coefficient
                ) % prime
                product[degree + 1] = (
                    product[degree + 1] + coefficient
                ) % prime
            basis = product
            denominator = denominator * (point - other) % prime
        scale = pow(denominator, -1, prime)
        for degree, coefficient in enumerate(basis):
            result[degree] = (
                result[degree] + coefficient * scale
            ) % prime
    return tuple(result)


def _validate(config: RelationPageConfig) -> None:
    if config.base.field_prime not in SCALABLE_FIELD_PRIMES:
        raise ValueError("the bound check requires an audited scalable field")
    if not config.pages.uses_global_frontier:
        raise ValueError(
            "layout does not declare global_frontier, so there is nothing to "
            "verify; the per-owner bound is already enforced at preparation"
        )


def program_name(config: RelationPageConfig) -> str:
    _validate(config)
    material = f"{BOUND_CHECK_VERSION}:{config.digest}".encode()
    return f"paged_bound_check_{hashlib.sha256(material).hexdigest()[:16]}"


def render_program(config: RelationPageConfig) -> str:
    """Render the one-time federation-wide bound check."""

    _validate(config)
    bound = config.pages.global_frontier
    # A key cannot hold more than this even if every owner is full, so the
    # comparison never has to consider wider values.
    max_possible = len(config.base.owners) * config.pages.slots_per_key
    count_bits = max(1, max_possible.bit_length())
    coefficients = overflow_polynomial(
        bound, max_possible, config.base.field_prime
    )

    rows = (
        config.dense_directory_rows
        if config.uses_hybrid_directory
        else config.directory_rows
    )
    return f'''# Generated one-time federation-wide bound check (EXPERIMENTAL).
# Verifies: no (source, relation) key holds more than GLOBAL_FRONTIER edges
# summed over every owner. Opens exactly one aggregate value.
from Compiler.library import print_ln_to, start_timer, stop_timer
from Compiler.types import Array, Matrix, sint

program.use_edabit(True)
program.timeout = None

SERVER_COUNT = 3
DIRECTORY_ROWS = {rows}
OWNER_COUNT = {len(config.base.owners)}
GLOBAL_FRONTIER = {bound}
COUNT_BITS = {count_bits}
OVERFLOW_COEFFICIENTS = {coefficients!r}


def shared_vector(length):
    result = Array(length, sint)
    result.input_from(0)
    for player in (1, 2):
        incoming = Array(length, sint)
        incoming.input_from(player)
        result.assign_vector(result[:] + incoming[:])
        incoming.delete()
    return result


# Each owner wrote its per-key count at the same position, so reconstruction
# already yields the federation-wide count. No unpacking, no oblivious read:
# this pass verifies every key, so every index here is public.
start_timer(1)
occupancy = shared_vector(DIRECTORY_ROWS)
stop_timer(1)

start_timer(2)
# Honest owner preparation promises occupancy in 0..OWNER_COUNT*SLOTS_PER_KEY.
# OVERFLOW_COEFFICIENTS interpolate the exact predicate 1[x>GLOBAL_FRONTIER]
# on that complete public domain. Horner evaluation is SIMD across all rows:
# no per-row compiler loop and no 125-bit comparison/bit decomposition.
counts = occupancy[:]
overflow = sint(OVERFLOW_COEFFICIENTS[-1], size=DIRECTORY_ROWS)
for coefficient in reversed(OVERFLOW_COEFFICIENTS[:-1]):
    overflow = overflow * counts + coefficient
violations = overflow.sum()
stop_timer(2)

# The single opened value. It says whether the declared bound holds, which
# declaring it already asserts publicly. It deliberately does not identify the
# offending keys: that would leak the degree distribution the bound summarizes.
for server in range(SERVER_COUNT):
    print_ln_to(server, 'PAGED_BOUND_VIOLATIONS %s', violations.reveal_to(server))
'''


def write_program(config: RelationPageConfig, output_dir: str | Path) -> Path:
    name = program_name(config)
    destination = Path(output_dir) / f"{name}.mpc"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_program(config), encoding="utf-8")
    return destination


def bound_check_cost_estimate(config: RelationPageConfig) -> dict[str, int | str]:
    _validate(config)
    return {
        "directory_rows": (
            config.dense_directory_rows
            if config.uses_hybrid_directory
            else config.directory_rows
        ),
        "comparisons": 0,
        "field_multiplications": (
            (config.dense_directory_rows
             if config.uses_hybrid_directory
             else config.directory_rows)
            * len(config.base.owners)
            * config.pages.slots_per_key
        ),
        "oblivious_reads": 0,
        "opened_values": 1,
        "private_input_values_per_server": (
            config.dense_directory_rows
            if config.uses_hybrid_directory
            else config.directory_rows
        ),
        "note": (
            "Every index is public because the check covers all keys, so this "
            "is a SIMD Horner evaluation of the bounded-domain overflow "
            "polynomial with no demux or bit decomposition. It assumes the "
            "honest-input range promised by owner preparation. Paid once at "
            "preparation, never per query."
        ),
    }
