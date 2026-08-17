# Threat Model

**Normative source: [`doram_t2_3pc/THREAT_MODEL.md`](../doram_t2_3pc/THREAT_MODEL.md).**
This file is the project-level summary; where the two differ, that one wins.

## The computation committee

Exactly three servers. A static **passive** adversary may corrupt and collude
with **any two** of them.

That is the strongest corruption threshold a three-server committee admits: with
3-of-3 additive sharing, three colluding servers trivially reconstruct, so
nothing above two is meaningful. It also means only **one** honest server is
required, which is a weaker deployment assumption than honest majority and the
right one for mutually distrusting participants.

It is *not* honest majority. Tolerating two corruptions out of three forces
dishonest-majority MPC, and that choice is expensive: holding the circuit fixed,
an honest-majority protocol is roughly **261x cheaper** on the term that grows
with the graph (`doram_t2_3pc/benchmarks/threat_model_cost_fork.json`). The cost
is deliberate, not accidental.

`doram_t2_3pc/protocols.py` enforces this: any protocol tolerating fewer than two
corrupted servers is **refused** unless `--allow-weaker-threat-model` is passed
explicitly, and a run under one prints a warning into its own output.

### Known discrepancy with the problem statement

`problem/problem.pdf` §0.5.1 states "no majority coalition of servers will
collaborate", which is **honest majority** — at most one corrupted server. The
implementation is deliberately stronger. If the specification is authoritative
for your purposes, then the implementation over-delivers and the 261x premium is
being paid for a guarantee the specification never required. That is a decision
to make consciously; it is recorded here rather than left as a silent conflict.

## Other parties

- **Data owners** and the **client** are not MPC parties. They deal shares in and
  read shares out. No dealer, no trusted setup, no plaintext aggregator.
- Owners prepare their shares **independently**, with no cross-owner
  coordination. Several design choices exist only to preserve that.
- Party-local indexes remain private.
- The client receives the ranked top-k evidence. That is the intended output.

## Adversary behaviour

Semi-honest only. Corrupted servers follow the protocol but pool their views.

The generated circuit also runs correctly under MASCOT, a malicious
dishonest-majority protocol, at roughly 31x wall-clock and 155x communication
(`benchmarks/malicious_protocol_overhead.json`). That does **not** make the
system maliciously secure: the owner-input and client-output boundaries are
unauthenticated, so a malicious owner or server can still corrupt results.

## What leaks

The claim is that the two-server view is simulatable from the public parameters
alone. Both the functionality and the leakage function are stated in
[`doram_t2_3pc/IDEAL_FUNCTIONALITY.md`](../doram_t2_3pc/IDEAL_FUNCTIONALITY.md),
with an executable simulator in `doram_t2_3pc/simulator.py`. What those public
parameters give away — chiefly per-owner data volume — is analysed against the
design in [`doram_t2_3pc/LEAKAGE_ABUSE.md`](../doram_t2_3pc/LEAKAGE_ABUSE.md).

## Out of scope

- Private LLM inference.
- Malicious-party security end to end (see above for what is and is not covered).
- Sublinear access. Every dependent read is a full linear pass; that is what
  gives the design no access-pattern or volume leakage, and it is why it is slow.
- Protection after `K_setup` compromise.
