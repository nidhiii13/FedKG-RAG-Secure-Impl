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
demux, no one-hot selector, and no oblivious indexing anywhere -- just one linear
pass with a comparison per row. Cost is ``directory_rows`` comparisons, paid once
at preparation, not per query.

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

from .config import SCALABLE_FIELD_PRIME
from .relation_pages import RelationPageConfig


BOUND_CHECK_VERSION = 1


def _validate(config: RelationPageConfig) -> None:
    if config.base.field_prime != SCALABLE_FIELD_PRIME:
        raise ValueError("the bound check requires field_prime=2^127-1")
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

    return f'''# Generated one-time federation-wide bound check (EXPERIMENTAL).
# Verifies: no (source, relation) key holds more than GLOBAL_FRONTIER edges
# summed over every owner. Opens exactly one aggregate value.
from Compiler.library import print_ln_to, start_timer, stop_timer
from Compiler.types import Array, Matrix, sint

program.use_edabit(True)
program.timeout = None

SERVER_COUNT = 3
DIRECTORY_ROWS = {config.directory_rows}
OWNER_COUNT = {len(config.base.owners)}
GLOBAL_FRONTIER = {bound}
COUNT_BITS = {count_bits}


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
violations = sint(0)
for row in range(DIRECTORY_ROWS):
    # A count above the bound would make the second hop drop matches silently.
    violations = violations + (occupancy[row] > GLOBAL_FRONTIER)
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
        "directory_rows": config.directory_rows,
        "comparisons": config.directory_rows,
        "oblivious_reads": 0,
        "opened_values": 1,
        "private_input_values_per_server": config.directory_rows,
        "note": (
            "Every index is public because the check covers all keys, so this "
            "is a linear pass with no demux. Paid once at preparation, never "
            "per query."
        ),
    }
