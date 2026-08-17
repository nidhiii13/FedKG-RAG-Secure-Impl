# Ideal functionality and leakage

`THREAT_MODEL.md` states informally what the servers may not learn. This document
states it as a functionality and a leakage function, so the claim is falsifiable
and so the gap between what is argued and what is proven is explicit.

**Status: this is a specification and a proof *sketch*, not a proof.** An
executable simulator exists (`simulator.py`), and it demonstrates that the view's
observable components are reproducible from `L` alone — but **no reduction has
been carried out**, and MP-SPDZ's own protocol security is assumed as a black
box. A simulator is not a simulation proof. Section 6 lists exactly what is
missing. Nothing here should be cited as "proven secure".

## 1. Parties

| Party | Count | Provides | Receives |
| --- | --- | --- | --- |
| Data owners `O_1..O_n` | n ≥ 1 | their own edge sets | nothing |
| Client `C` | 1 | the query batch | the ranked answers |
| Servers `S_0, S_1, S_2` | exactly 3 | nothing | nothing |

Owners and the client are **not** MPC parties. They deal shares in and read
shares out. The computation itself is exactly the three servers.

## 2. Public parameters

Every one of these is known to everyone, including the adversary. They are fixed
before any data is shared and are part of the layout digest.

```
n                    number of owners
E                    entity universe size
R                    relation universe size
k                    top-k width
p                    page_size            slots per page
m                    pages_per_key        pages reachable from one directory entry
B_1..B_n             page_budget          pages in each owner's pool
f                    frontier_per_owner   first-hop matches carried per owner
g                    global_frontier      OPTIONAL: first-hop matches carried
                                          across the whole federation
b                    directory_buckets    OPTIONAL: buckets in the compact
                                          directory (power of two)
s                    bucket_slots         OPTIONAL: slots per owner per bucket
Q                    queries in the batch
```

`b` and `s` appear only under the compact directory (`compact_directory.py`),
which sizes the index to the number of keys rather than to `E * R`.

`b` is a free public choice. **`s` is only leakage-free if it is derived from the
public bound** (`public_capacity_bound`), which is a function of `b` and the
public per-owner key count. If it is instead set to the *measured* worst-case
bucket load — which `plan_capacity` does, for cost analysis — then `s` is a
public parameter whose value depends on how the owners' keys cluster, and it
belongs in this function as a genuine disclosure. `LEAKAGE_ABUSE.md` §8 records
that correction and measures what the safe choice costs.

`s` is uniform across owners, so it is sized for the largest: under volume skew
the smaller owners' slots sit empty and the padding cost scales with the skew.

`g` is qualitatively different from every other parameter here and deserves the
distinction. All the others are declarations about **one** party's data, made by
that party. `g` is a declaration about the **union**: it asserts that no
`(source, relation)` key has more than `g` matching edges summed over every
owner. Publishing it therefore reveals a joint property of the federation that
no participant could have disclosed alone. It is included in `L` deliberately —
see `LEAKAGE_ABUSE.md` §7 for what it gives away and why it is still usually the
better trade.

## 3. The functionality `F_FedKG2Hop`

Owner `O_i` submits an edge set `G_i ⊆ E × R × E × Evidence × Score`, subject to
the declared bounds:

- **B1** for every `(s, r)`: `|{(s,r,·,·,·) ∈ G_i}| ≤ p · m`  (storage bound)
- **B2** for every `(s, r)`: `|{(s,r,·,·,·) ∈ G_i}| ≤ f`      (dependent-read bound)

These are not independent. Configuration validation already forces `f ≤ p · m`,
so **B2 implies B1**, and B2 is the binding constraint. B1 is nonetheless checked
first, because it produces the diagnostic that names the storage parameter the
operator actually has to raise. Both are enforced **fail-closed** at preparation,
before anything is shared: an owner that violates them is rejected, never
truncated. That is what makes the fixed-width compaction in §5(d) lossless rather
than silently lossy — the circuit compacts to `f` slots without checking for
overflow, so the guarantee has to come from preparation.

The client submits `q = (s, r_1, r_2)`. Write `G = ⋃_i G_i`. Then:

```
H_1 = { (t, ev, sc)                       : (s, r_1, t, ev, sc) ∈ G }
H_2 = { (ev_1, ev_2, sc_1 + sc_2)         : (t, ev_1, sc_1) ∈ H_1,
                                            (t, r_2, t_2, ev_2, sc_2) ∈ G }
```

`F` returns to `C` the `k` highest-scoring elements of `H_2` under the declared
deterministic tie-break, optionally deduplicated by terminal entity. `F` returns
**nothing at all** to `S_0, S_1, S_2` and nothing to the owners.

## 4. The leakage function

For a static passive adversary corrupting **any two** of the three servers, plus
any subset of owners, the claim is that its entire view is simulatable from:

```
L = ( n, E, R, k, p, m, B_1..B_n, f, g, Q )
```

That is: **the leakage is exactly the public parameters and the batch size.** `L`
is a function of the declared configuration alone — it does not depend on `G`, on
`q`, or on which entities matched.

In particular the following are claimed *not* to leak to two colluding servers:

- the query `(s, r_1, r_2)`,
- any first-hop target — this is what forbids revealing hop-one results before
  hop two,
- any returned entity, evidence handle, or score,
- **how many matches each owner contributed**, including whether an owner
  contributed none at all,
- the realized degree of any key, as opposed to its declared upper bound.

## 4a. Definition: contribution hiding

Section 4 says the whole view is simulatable from `L`. One consequence deserves
its own name, because it is the property this system exists to provide and the
one a federation of competitors actually cares about: **the servers cannot tell
which owner supplied an answer, or how much any owner supplied.**

> **Definition 1 (Contribution hiding).**
> Fix public parameters `L` and a query batch `q`. Let `G = (G_1, …, G_n)` and
> `G' = (G'_1, …, G'_n)` be two owner profiles such that
>
> 1. both satisfy the bounds declared in `L`, and
> 2. they induce the same answer, `F(G, q) = F(G', q)`.
>
> Then for every set `C` of at most two servers, the views satisfy
>
>     View_C(G, q)  ≡  View_C(G', q)
>
> where `≡` is identical distribution, not computational indistinguishability.

Note what the quantifier permits. `G'` may move every matching edge from one
owner to another, may give one owner all the matches and another none, and may
change each owner's per-query match count arbitrarily. The definition says none
of that is observable. What it may **not** change is the answer, or the declared
bounds.

**Why the implementation satisfies it.** The compaction step emits exactly
`f` frontier slots per owner — or `g` slots federation-wide when a global
frontier is declared — regardless of how many actually matched. Occupancy rides
in secret validity bits. So the instruction trace and message volumes are
functions of `L` alone, and §5(b) and §5(d) establish that. Two profiles
agreeing on `L` and on the answer therefore produce identical views.

**What Definition 1 does not cover**, and must not be read as covering:

- **Per-owner data volume.** `B_i` is in `L`, so `G` and `G'` must agree on it.
  Two profiles where one owner holds twice as much are *not* related by the
  definition. Hiding that is a separate property, addressed by
  `volume_hiding.py`; see `LEAKAGE_ABUSE.md` §2.
- **The client.** Definition 1 quantifies over sets of at most two *servers*. It
  says nothing about what the client learns, and §8 shows the client can defeat
  it outright when evidence handles are allocated per owner.
- **Malicious behaviour.** `View_C` is the view of a passive adversary following
  the protocol.

## 5. Proof sketch, and why each step is plausible

**(a) The shares carry nothing.** Every server input is an additive 3-out-of-3
share over `F_P`. Any two shares of a value are uniform and independent of it.
The *shapes* of the shared arrays — directory `E·R × n`, pool `n × (B_i + m − 1) × p`
— are functions of `L` alone, so a simulator can sample uniform arrays of the
right shape.

**(b) The circuit is data-independent.** The generated program has no branch on a
secret and no secret-dependent memory access. Every table read is a full pass:
`read_directory` scans all `E·R` rows under a one-hot selector, `read_page_window`
scans the whole pool. The instruction trace is therefore a function of `L` alone.
This is machine-checked — see §7.

**(c) Nothing is opened except masked output.** The only `reveal` in the circuit
is three per output field: `share_0, share_1` are fresh `sint.get_random()` and
`share_2 = value − share_0 − share_1`. Server `S_j` sees only `share_j`. Any two
of the three are uniform and independent of `value`. This too is machine-checked.

**(d) Contribution hiding is structural, not statistical.** Compaction always
emits exactly `f` slots per owner regardless of how many matched; occupancy rides
in secret validity bits. An owner with zero matches and an owner with `f` matches
produce identical instruction traces and identical message volumes.

Given (a)–(d), the two corrupted servers' joint view consists of uniform shares
plus a trace determined by `L`, which a simulator can produce. That is the
argument. It is not a proof.

## 6. What is NOT proven, and what would break

1. **A simulator exists, but not a proof.** `simulator.py` builds a server view
   from `L` alone -- no edges, no queries, no shares, and its signature is
   test-enforced to keep it that way. `test_simulator.py` checks that the
   simulated view matches a real one in every observable component, and runs
   Definition 1 executably: it swaps `owner_a`'s and `owner_b`'s edge sets,
   confirms the answer is unchanged, and confirms the resulting views are
   indistinguishable although every per-owner contribution differs.

   That is **not** a simulation proof. A proof is a reduction showing no
   distinguisher gains non-negligible advantage, and it must reason about
   MP-SPDZ's own protocol security, which is assumed here as a black box. What
   the simulator establishes is that the components such a proof would have to
   reproduce **are** reproducible from `L`, and that losing that property becomes
   a test failure rather than a silent regression.
2. **Malicious behaviour is out of scope.** Under MASCOT the same circuit runs
   correctly (`benchmarks/malicious_protocol_overhead.json`), but the owner-input
   and client-output boundaries are unauthenticated, so a malicious owner or
   server can corrupt results. `F` above assumes honest inputs.
3. **`B_i` is public and is a real leak about owner `i`.** It is the size of that
   owner's page pool, which is essentially its distinct-`(source, relation)` key
   count — a direct statement about how much data that owner holds. This is
   *inside* `L` by construction, so it does not violate the claim, but it means
   the claim is weaker than "the servers learn nothing about the owners."
   See `LEAKAGE_ABUSE.md`.
4. **`f`, `p`, `m` publish upper bounds on the degree distribution.** Same status:
   in `L`, deliberately, and analyzed separately.
5. **`g` is not enforceable owner-locally, and is currently trusted.**
   `f` is checked by each owner against its own data, fail-closed, before any
   share is produced. `g` bounds a cross-owner sum that no owner can see.
   `check_global_frontier` verifies it offline against the plaintext union,
   which exists for fixtures and simulation but **not in a deployment**. The
   deployment-grade equivalent is a one-time preparation-phase MPC pass over
   the directory; it is **not implemented**. Until it is, a layout declaring
   `g` rests on an unverified assumption, and if `g` is understated the second
   hop silently drops matches rather than failing closed. This is the weakest
   link in the current design.
6. **The honest-majority variant is a different claim entirely.** Under
   `--protocol atlas` the assumption is at most *one* corrupted server, and the
   two-server statements in §4 are simply false. See `protocols.py`.

## 7. Which parts are machine-checked

`tests/unit/test_ideal_functionality.py` checks the structural claims that §5
rests on, against the generated circuit text for several configurations:

| Claim | Check |
| --- | --- |
| (b) no secret-dependent control flow | no `if_`/`while_` over a secret; every table read is a full-width scan |
| (b) trace depends only on `L` | two configs with identical public parameters but different data produce byte-identical circuits |
| (c) only masked output is opened | exactly `3` reveals per output field, each preceded by fresh randomness; no bare `.reveal()` |
| (d) contribution hiding | compaction emits exactly `f` slots per owner unconditionally; the emitted width is independent of the data |
| Definition 1, executably | swapping two owners' edge sets leaves the answer unchanged and the views indistinguishable, though every per-owner contribution differs |
| the simulator uses only `L` | its signature is asserted to accept no edges, queries, or shares |
| bounds are fail-closed | preparation rejects an owner violating B1 or B2 rather than truncating |

The checks are structural — they constrain the generated program. They do not
substitute for a simulation proof, and they cannot: no test can establish that a
protocol *composes* securely.

## 8. Scope of contribution hiding — read this before relying on it

Contribution hiding as stated in §4 is a property **against the servers**. It is
*not* automatically a property against the client, and in the bundled fixtures it
does not hold against the client at all.

The client receives evidence handles. If handles are namespaced per owner — as
— as `examples/ten_query` **used to**, where `owner_a` held `101..105`, `owner_b`
`201..205`, `owner_c` `301..306` — then the returned handle names the contributing
owner directly. The client learns exactly which owner supplied each answer, and
by counting, how many each supplied.

**The bundled fixture no longer does this.** Its handles were reallocated
owner-blind, drawn uniformly from the 2^50 evidence space with an independent
generator per owner, so the ranges interleave and a handle identifies nothing.
`test_evidence_handles.py` asserts the shipped fixture is clean and proves the
detector still fires on a constructed per-owner allocation.

This is a property of the *handle allocation*, not of the circuit, and the circuit
cannot fix it: the client is supposed to receive the handle in order to fetch the
evidence. Three coherent positions, and a deployment must pick one explicitly:

1. **Provenance is intended.** The client is meant to know the source. Then
   contribution hiding is a server-side property only, and §4 should be read as
   scoped to `S_0, S_1, S_2` — which is how it is written.
2. **Provenance must be hidden from the client too.** Then handles must be drawn
   from a single owner-independent namespace — for example a pseudorandom token
   whose mapping to `(owner, record)` is held by a separate service the client
   cannot correlate — and the fixtures must be rebuilt.
3. **Provenance is hidden but evidence is still fetchable.** Requires an
   oblivious retrieval step for the evidence itself, which is not implemented and
   would be a second protocol.

The bundled fixtures take position 1 by accident rather than by decision.

Position 2 is now **available and enforced**: `evidence_handles.py` provides
`allocate_owner_blind_handles`, which draws each handle uniformly from the whole
evidence space, independently per owner and with **no coordination** — preserving
the property that owners prepare their shares alone. With `evidence_bits = 50`
the space is about 1.1e15, so collisions are negligible at any realistic
federation size.

It also provides `handles_leak_owner`, which detects a leaking allocation. That
detector checks two independent tells, and the second exists because the first
was not enough: seeding every owner's generator identically produces *overlapping*
ranges — passing a naive range check — while emitting the **same handle sequence**
for every owner, which is worse than per-owner numbering rather than better. That
failure was found by running the detector against its own remedy.

The fixture has been reallocated, so position 2 is what ships. One recorded
benchmark, `frontier_compaction_microbenchmark.json`, cites handle values from
the old allocation; it is already marked superseded in `benchmarks/STATUS.md`
for unrelated reasons, and its cited handles predate this change.
