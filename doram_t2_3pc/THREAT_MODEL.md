# Threat model and security argument

This prototype targets exactly three computation servers and a static,
semi-honest adversary that may corrupt and collude with any two of them. Thus,
there must be at least one non-colluding server, but there is no honest-majority
assumption. Data owners and the query client are external roles, not members of
the computation committee.

The runtime is pinned to MP-SPDZ `semi-party.x` through `Scripts/semi.sh`. The
bundled MP-SPDZ protocol table classifies Semi as OT-based, semi-honest,
dishonest-majority computation. Rep3, replicated-ring, and Shamir runners are
not selectable here because they use a different corruption assumption.

## What the argument establishes

External values are additively shared over the exact prime selected by the
public configuration. The legacy fixture uses `p = 2^61 - 1`; packed scalable
fixtures use `p = 2^127 - 1`. Two shares are independently uniform field elements and the
third is their modular correction. For any fixed view of any two servers and
any possible secret, exactly one missing share is consistent with that secret.
Consequently, a view containing at most two input shares is independent of the
input value.

Inside MPC, the three private inputs are summed and remain secret. The legacy
backend holds graph blocks in MP-SPDZ `OptimalORAM`. The packed-scan backend
implements an oblivious read by constructing a secret one-hot selector and
touching every public graph bucket; therefore it is linear-scan DORAM, not a
sublinear ORAM. The source address is secret; each matching
first-hop record supplies a secret second-hop address. Invalid first-hop slots
read the real dummy block at address zero. Every query executes the same number
of reads, comparisons, and top-k operations for the public configuration.

The result is not opened to a computation server. MPC samples two fresh full-
field masks and privately gives one output share to each server; the client
reconstructs all three. Any two output shares are therefore insufficient to
learn the result. Under MP-SPDZ Semi's passive-security assumptions and its OT
primitives, these facts compose to protect graph/query contents and logical
accesses against up to two colluding passive servers.

This is an implementation-level argument, not a new cryptographic proof or a
security audit. A paper should state the ideal functionality and simulator
formally, cite the selected MPC and ORAM results, and have the final system
reviewed independently.

## Explicit leakage

The compute servers learn the public entity and relation namespaces, owner
count and identities, per-owner fanout bound, top-k, program shape, one query
execution, and public message/file sizes. The query client learns the returned
validity bits, scores, and evidence handles. An owner naturally knows its own
records. This code does not hide machine/network metadata outside the fixed MPC
transcript, nor does it implement transport authentication, secure deletion,
host hardening, or an evidence vault.

The three `run_party.py` processes must execute on separately administered
hosts and each host must receive only its own input and output shares. The
single-host `run_mpspdz.py` harness deliberately exists for correctness and
performance tests; it centralizes all shares and therefore does not instantiate
the stated non-collusion assumption.

Semi-honest means corrupted servers follow the program but inspect and combine
their views. It does not stop malformed messages, incorrect computation, input
substitution, or selective abort. If those attacks are in scope, the backend
must move to a malicious dishonest-majority protocol such as MASCOT and the
surrounding input/output channels must also be authenticated.
