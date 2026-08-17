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

The privacy argument assumes honest input formation by the external owners and
client. They need not trust one another or the servers with plaintext, but this
implementation does not prove that their three submitted shares encode the
same well-formed record or query. Malicious external inputs are addressed under
"Integrity limitations" below.

## What the argument establishes

External values are additively shared over the exact prime selected by the
public configuration. The legacy fixture uses `p = 2^61 - 1`; packed scalable
fixtures use `p = 2^127 - 1`. Two shares are independently uniform field elements and the
third is their modular correction. For any fixed view of any two servers and
any possible secret, exactly one missing share is consistent with that secret.
Consequently, a view containing at most two input shares is independent of the
input value.

Inside MPC, the three private inputs are summed and remain secret. The legacy
backend holds graph blocks in MP-SPDZ `OptimalORAM`. The supported packed-scan
backend implements a secret-index lookup by constructing a secret one-hot
selector and touching every public graph bucket. It is best described as a
packed batched MPC-oblivious linear scan, not as a sublinear or persistent
ORAM. The source address is secret; each matching
first-hop record supplies a secret second-hop address. Invalid first-hop slots
read the real dummy block at address zero. Every query executes the same number
of reads, comparisons, and top-k operations for the public configuration.

If the optional public per-owner `(source, relation)` capacity is smaller than
the total source fanout, each owner's matching first-hop slots are stably
compacted inside MPC before the second scan. The circuit still executes the
same fixed number of slots for every query. Match counts, validity bits,
matching owners, and dependent addresses are not opened. The owner-side
preparer fails instead of truncating if either declared capacity is exceeded.

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
count and identities, source-wide fanout bound, optional relation-fanout bound,
batch size, top-k, answer-deduplication policy, circuit shape, execution timing,
and public message/file sizes. Fixed padding hides the realized per-source and
per-relation degrees from field contents, assuming a server sees only its own
uniform additive shares, but it does not hide these public upper bounds or the
owner endpoints that submit shards.

The query client learns the returned validity bits (and therefore returned
cardinality up to `top_k`), scores, and evidence handles. Evidence handles are
stable identifiers and can reveal provenance or support cross-query linkage if
the application-level evidence vault exposes such structure. The servers see
only fresh output shares. An owner naturally knows its own records. This code
does not hide machine/network metadata outside the fixed MPC transcript, nor
does it implement authenticated shard delivery, secure deletion, host
hardening, rate limiting, or an evidence vault.

The three `run_scan_party.py` processes (or `run_party.py` for the legacy
backend) must execute on separately administered hosts, and each host must
receive only its own input and output shares. The single-host
`run_scan_mpspdz.py`/`run_mpspdz.py` harnesses deliberately exist for
correctness and performance tests; they centralize all shares and therefore do
not instantiate the stated non-collusion assumption.

The corruption bound must hold over the lifetime of the shares. An adversary
that compromises different servers over time and eventually obtains all three
stored shards reconstructs the inputs; proactive refresh and erasure are not
implemented. Query and output sharing use fresh randomness when their
preparation/circuit is rerun. Reusing the exact same query-share files lets a
corrupted server or coalition link those executions by equality of its input
shares even though it still cannot recover the query. The implementation does
not prevent such reuse. Traffic observers may also link executions by endpoint
and timing.

## Integrity limitations

Semi-honest means corrupted servers follow the program but inspect and combine
their views. It does not stop malformed messages, incorrect computation, input
substitution, or selective abort. If those attacks are in scope, the backend
must move to a malicious dishonest-majority protocol such as MASCOT and the
surrounding input/output channels must also be authenticated.

Half of that has now been measured rather than assumed. The generated circuit
runs unmodified under `mascot-party.x` (malicious, dishonest majority — the same
three-party, up-to-two-corruption threshold as Semi) and returns results matching
the cleartext oracle exactly, at roughly 31x wall-clock and 155x communication;
`benchmarks/malicious_protocol_overhead.json` records the run. That establishes
only that the circuit needs no passive-only construct and what the swap costs.
**It does not make this system maliciously secure**, and no claim in this
repository says otherwise: the second half of the requirement — authenticated
owner input and authenticated output release — remains unimplemented, so both
trust boundaries outside the MPC are still exactly as described below.

Likewise, an owner or client that bypasses the provided preparer can submit
inconsistent additive shares or an out-of-range semantic value. For
preparer-formed bounded encodings, the MPC circuit range-checks addresses used
for table access and maps invalid targets to the dummy block. That check is not
a canonicality proof for an arbitrary full-field value assembled from
malicious shares. The implementation does not authenticate datasets, prove
packed-record canonicality, enforce cross-server share consistency, or
guarantee that the declared fanout promise holds for adversarially formed
shares. These failures can corrupt or suppress results without revealing an
honest party's plaintext under the passive-server model. Robust ingestion
requires commitments or MAC/authenticated sharing plus in-MPC validation and a
defined abort policy.
