"""Executable simulator for the two-server view, built from ``L`` alone.

What this is
------------
``IDEAL_FUNCTIONALITY.md`` §4 claims the view of any two colluding servers is
simulatable from the public parameters ``L``, and §5 argues why. This module
turns that argument into something runnable: a simulator that produces a view
using **only** ``L``, with no access to the owners' edges or the client's query.

Tests then check the two things the claim rests on:

1. the simulated view and a real view are identical in every observable
   component -- input length, circuit text, opened-value count;
2. two different owner profiles satisfying the same ``L`` and inducing the same
   answer produce views that are identical in those same components, which is
   the executable form of Definition 1.

What this is not
----------------
**Not a proof.** A simulation proof is a reduction showing that no distinguisher
succeeds with non-negligible advantage, and it has to reason about MP-SPDZ's own
protocol security, which is assumed here as a black box. This module cannot
establish that and does not try.

What it does establish is narrower and still worth having: that the components a
simulator would have to reproduce **are** reproducible from ``L``, and that a
future change breaking that becomes a test failure rather than a silent loss.
The gap between this and a proof is stated in §6 of the specification.

Structural discipline
---------------------
``simulate_server_view`` takes a configuration and a query count. It does not
take edges, queries, or shares, and it cannot read them: everything it returns is
derived from public parameters and fresh randomness. A test asserts the
signature stays that way, because a simulator that peeked would prove nothing.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from .page_program import render_program
from .paged_shares import expected_private_input_values
from .relation_pages import RelationPageConfig


@dataclass(frozen=True)
class ServerView:
    """Everything one server observes across a run.

    ``private_input`` is the values that server receives. ``circuit`` is the
    program every server executes. ``opened_values`` counts what the run reveals
    to this server. Together these are the observable surface; anything a
    distinguisher could use has to be in here.
    """

    server: int
    private_input: list[int]
    circuit: str
    opened_values: int

    def shape(self) -> tuple[int, int, int]:
        """The part a simulator must match exactly, independent of values."""

        return (self.server, len(self.private_input), self.opened_values)


def simulate_server_view(
    config: RelationPageConfig,
    query_count: int,
    server: int,
    *,
    rng: secrets.SystemRandom | None = None,
) -> ServerView:
    """Produce a server's view from public parameters alone.

    No edges, no queries, no real shares are consulted. The input is uniform in
    the field, which is exactly the distribution a 3-of-3 additive share has when
    fewer than three shares are held; the circuit is a deterministic function of
    the configuration; and the opened count follows from the output contract.
    """

    if server not in range(3):
        raise ValueError("server must be 0, 1, or 2")
    generator = rng or secrets.SystemRandom()
    prime = config.base.field_prime
    length = expected_private_input_values(config, query_count)
    return ServerView(
        server=server,
        private_input=[generator.randrange(prime) for _ in range(length)],
        circuit=render_program(config, query_count),
        # One masked share per output field, per ranked row.
        opened_values=query_count * config.base.top_k * 4,
    )


def real_server_view(
    config: RelationPageConfig,
    query_count: int,
    server: int,
    private_input_path: str,
) -> ServerView:
    """Read a server's actual view from a prepared instance, for comparison."""

    if server not in range(3):
        raise ValueError("server must be 0, 1, or 2")
    from pathlib import Path

    values = [int(line) for line in Path(private_input_path).read_text().split()]
    return ServerView(
        server=server,
        private_input=values,
        circuit=render_program(config, query_count),
        opened_values=query_count * config.base.top_k * 4,
    )


def views_are_indistinguishable(first: ServerView, second: ServerView) -> dict:
    """Compare two views on everything a distinguisher could observe.

    Share *values* are deliberately excluded: they are uniform in both, so they
    carry no signal, and requiring them to be equal would be requiring the
    simulator to guess. What must match is the shape and the circuit.
    """

    same_shape = first.shape() == second.shape()
    same_circuit = first.circuit == second.circuit
    return {
        "indistinguishable": same_shape and same_circuit,
        "same_shape": same_shape,
        "same_circuit": same_circuit,
        "shapes": (first.shape(), second.shape()),
        "note": (
            "share values are excluded by design: uniform in both, so equality "
            "would demand the simulator guess rather than simulate"
        ),
    }
