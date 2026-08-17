"""The MPC protocols this prototype may be run under, and what each one assumes.

This module exists because the protocol binary is the single setting that
silently changes the security claim. Passing ``atlas-party.x`` instead of
``semi-party.x`` is a one-word edit that replaces "any two of three servers may
collude" with "at most one server may be corrupted" -- a strictly weaker
assumption that two colluding servers break completely.

So protocol selection is a named choice here rather than a free-form string, and
anything weaker than the project's declared threat model requires an explicit
opt-in that has to be typed on the command line every single time.

See ``benchmarks/threat_model_cost_fork.json`` for what the declared threat
model costs: holding the circuit fixed, honest majority is roughly 261x cheaper
on the term that grows with the graph. That measurement is an argument for
making the choice deliberately, not an argument for weakening it.
"""

from __future__ import annotations

from dataclasses import dataclass


# The project's threat model: exactly three servers, any two of which may be
# passively corrupted and may pool their views. THREAT_MODEL.md is normative.
DECLARED_MAX_CORRUPTED_SERVERS = 2


@dataclass(frozen=True)
class Protocol:
    """One MP-SPDZ protocol together with the security model it provides."""

    key: str
    script: str
    binary: str
    max_corrupted_servers: int
    malicious: bool
    summary: str

    @property
    def honest_majority(self) -> bool:
        return self.max_corrupted_servers < DECLARED_MAX_CORRUPTED_SERVERS

    @property
    def weaker_than_declared(self) -> bool:
        return self.max_corrupted_servers < DECLARED_MAX_CORRUPTED_SERVERS

    def describe(self) -> str:
        adversary = "malicious" if self.malicious else "semi-honest"
        majority = "honest majority" if self.honest_majority else "dishonest majority"
        return (
            f"{self.key}: {adversary}, {majority}, tolerates up to "
            f"{self.max_corrupted_servers} corrupted server(s) of 3"
        )


PROTOCOLS: dict[str, Protocol] = {
    "semi": Protocol(
        key="semi",
        script="semi.sh",
        binary="semi-party.x",
        max_corrupted_servers=2,
        malicious=False,
        summary=(
            "Matches the declared threat model. Semi-honest, dishonest majority, "
            "mod prime. This is the protocol every headline benchmark uses."
        ),
    ),
    "mascot": Protocol(
        key="mascot",
        script="mascot.sh",
        binary="mascot-party.x",
        max_corrupted_servers=2,
        malicious=True,
        summary=(
            "Same corruption threshold as semi, but tolerates actively deviating "
            "servers. Roughly 31x slower and 155x more communication. Note this "
            "does NOT make the system maliciously secure end to end: the owner "
            "input and client output boundaries are still unauthenticated."
        ),
    ),
    "atlas": Protocol(
        key="atlas",
        script="atlas.sh",
        binary="atlas-party.x",
        max_corrupted_servers=1,
        malicious=False,
        summary=(
            "WEAKER THREAT MODEL. Semi-honest, HONEST majority: security holds "
            "only while at most one of the three servers is corrupted. Two "
            "colluding servers recover every secret, including the query and the "
            "owners' edges. Roughly 261x cheaper on the term that grows with the "
            "graph. Use only for measuring what the declared threat model costs, "
            "or for a deployment where non-collusion of two servers is genuinely "
            "enforced by something other than assumption."
        ),
    ),
}

DEFAULT_PROTOCOL = "semi"


def resolve(key: str, *, allow_weaker_threat_model: bool = False) -> Protocol:
    """Look up a protocol, refusing a silent downgrade of the threat model.

    ``allow_weaker_threat_model`` has to be passed explicitly to select anything
    that tolerates fewer corrupted servers than ``THREAT_MODEL.md`` declares. It
    is deliberately not a configuration field: a stored layout must not be able
    to weaken the security of a run.
    """

    if key not in PROTOCOLS:
        known = ", ".join(sorted(PROTOCOLS))
        raise ValueError(f"unknown protocol {key!r}; known protocols: {known}")
    protocol = PROTOCOLS[key]
    if protocol.weaker_than_declared and not allow_weaker_threat_model:
        raise ValueError(
            f"protocol {key!r} tolerates only "
            f"{protocol.max_corrupted_servers} corrupted server(s), but this "
            f"project declares a threat model of "
            f"{DECLARED_MAX_CORRUPTED_SERVERS}. Re-run with "
            "allow_weaker_threat_model=True (CLI: --allow-weaker-threat-model) "
            "if you intend to measure or deploy under the weaker assumption, "
            "and label every resulting number accordingly."
        )
    return protocol
