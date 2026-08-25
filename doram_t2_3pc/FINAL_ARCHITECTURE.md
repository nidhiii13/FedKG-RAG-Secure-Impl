# Final architecture decision

## Selected research prototype

The selected passive-security design is the version-12 relation-paged circuit
in `page_program.py`, executed by exactly three MP-SPDZ **Temi** parties over
the NTT-compatible field
`170141183460469231731687303715885907969`. Data owners and the client remain
external. They generate fresh 3-out-of-3 additive shares under that exact
field; shares from the Mersenne-field Semi configuration are incompatible and
must never be reused.

The public KG-aware layout is relation keyed. Each owner stores fixed-size,
padded consecutive page windows and a padded directory. Inside MPC the circuit
performs a secret relation-aware first lookup, stable federation-wide frontier
compaction, dependent second lookup at secret hop-one targets, secret path
formation, terminal-aware global top-k, and fresh client-only output resharing.
All logical table accesses remain full linear scans of their public partitions.

If `global_frontier` is enabled, retrieval is authorized operationally only
after `bound_check_program.py` returns zero violations on occupancy shares from
the same owner-shard/configuration epoch. Version 3 evaluates the exact
overflow predicate with a bounded-domain polynomial and opens only the total
violation count. This optimization relies on the existing passive-input
assumption that owners used the range-checking preparer; it is not sound against
an actively malformed occupancy outside the promised domain.

## Why Temi is selected

Temi retains the declared static passive threshold: any two of the three
servers may collude, provided all corrupted servers follow the protocol. It is
not an honest-majority downgrade. On the controlled ten-query fixture it was
faster and lower-bandwidth than both Semi and Hemi. On the
100,000-entity/160,000-edge degree-one fixture it completed one exact query in
8.768 seconds with 2,608 MB global communication, including preprocessing.
The same v12 circuit under Semi required 26.759 seconds and 44,693 MB. The
fresh Temi-field shares passed the one-time MPC frontier check before retrieval.

Semi remains the compatibility and reproducibility baseline. Hemi remains a
valid same-threshold comparison backend. ATLAS is excluded from the selected
claim because it tolerates only one corrupted server. MASCOT is not selected as
the final security claim because changing the MPC engine does not authenticate
owner ingestion or client output release; the repository therefore has no
end-to-end malicious-security implementation.

## Defensible novelty claim

The implementation does **not** introduce a new cryptographic primitive or a
sublinear DORAM. Its defensible contribution is a systems/protocol composition
for private federated KG evidence retrieval: owner-independent contribution,
secret relation-aware dependent two-hop addressing, federation-wide bounded
frontier compaction, client-only ranked reconstruction, and a KG-aware paged
layout evaluated under a passive two-of-three corruption threshold. The
relation-folded layout and HE-backed execution are engineering contributions
within that composition.

## Claim that may be made

On one favorable synthetic fixture with 100,000 entities, 160,000 edges and
three owners, the prototype returned the exact independent-oracle top-k result
for a dependent relation-aware two-hop query under MP-SPDZ Temi's passive
dishonest-majority model. With a separately MPC-verified public global frontier
of one, the retrieval used 8.768 seconds and 2,608 MB global communication on
three localhost parties, preprocessing included.

## Claims that may not be made

- sublinear DORAM or ORAM access;
- malicious or production security;
- WAN or multi-host performance;
- general 160k-graph scalability from one degree-one query;
- full uncapped MetaQA or any completed WebQSP DORAM evaluation;
- negligible communication (2.61 GB per query remains high);
- novel FSS, DPF, PIR, ORAM, sharing, ranking, or MPC primitives;
- authenticated owner inputs, authenticated output delivery, proactive share
  refresh, private updates, or an oblivious evidence-vault fetch.

## What remains for a stronger paper

The next research step is architectural, not another local circuit tweak:
replace the linear directory/page scans with a genuinely sublinear dependent
read whose key distribution is proven private against every allowed pair of
servers, or revise the committee/trust model explicitly. Separately, an
end-to-end malicious variant needs authenticated owner commitments or
authenticated shares, in-circuit consistency/range checks, authenticated
client output release, and a defined abort policy. Evaluation still needs many
distinct queries, uncapped MetaQA/WebQSP capacity studies, LAN/WAN multi-host
runs, repeated trials, memory/preprocessing separation, and comparisons against
PIR/FSS/ORAM alternatives under matched corruption assumptions.
