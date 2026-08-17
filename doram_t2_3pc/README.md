# Three-server semi-honest private lookup prototype

This directory is a clean implementation path for two-hop federated KG
retrieval with a fixed three-server MPC committee. It does not reuse the old
design in which the query gateway and data owners are MP-SPDZ players.

Security documents, in the order worth reading them:

| Document | What it is for |
| --- | --- |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | normative: who is trusted, what is assumed |
| [`IDEAL_FUNCTIONALITY.md`](IDEAL_FUNCTIONALITY.md) | the functionality, the leakage function `L`, a proof **sketch**, and what is not proven |
| [`LEAKAGE_ABUSE.md`](LEAKAGE_ABUSE.md) | what an adversary can actually do with `L` — written against our own design |
| [`protocols.py`](protocols.py) | the protocols a run may use, and which ones weaken the threat model |

The design supports any public number of data owners. Each owner locally pads
every public source-entity bucket to `fanout_per_owner`, creates a 3-out-of-3
additive sharing, and sends one shard to each computation server. The client
does the same for `(source, relation_1, relation_2)`. No plaintext aggregation
party is required.

Within MPC, all owners' fixed sub-buckets form one block at each entity
address. The first secret address retrieves possible first-hop edges. Each
fixed first-hop position then causes a second ORAM lookup at its secret target
address (or dummy address zero). Relation filtering and stable top-k happen
without opening intermediate values. The client reconstructs output shares
from all three servers.

For small arrays MP-SPDZ's `OptimalORAM` deliberately uses a linear ORAM; above
its internal threshold it switches to recursive Path ORAM. Both hide the
logical address, but only the latter gives the intended sublinear-access
scaling. The main scaling parameter is
`B = owner_count * fanout_per_owner`: this prototype performs `B` adaptive
second reads and considers `B^2` paths. It is functionally N-owner, but large N
requires a stronger layout (for example, oblivious compaction into a global
fanout bound) to remain practical.

## Minimal workflow

Create a public config like `examples/config.json`. Entity slot zero, relation
ID zero, and evidence handle zero are reserved.

Each owner runs this only on its own trusted machine:

```bash
python3 -m doram_t2_3pc.prepare owner \
  --config doram_t2_3pc/examples/config.json --owner hospital_a \
  --edges doram_t2_3pc/examples/hospital_a.json --output-dir owner_a_shards
```

The query client similarly runs:

```bash
python3 -m doram_t2_3pc.prepare query \
  --config doram_t2_3pc/examples/config.json \
  --query doram_t2_3pc/examples/query.json --output-dir query_shards
```

After receiving only its own shard from every owner and the client, server `s`
assembles `Input-Ps-0` locally. Repeat with server IDs 0, 1, and 2:

```bash
python3 -m doram_t2_3pc.prepare assemble \
  --config doram_t2_3pc/examples/config.json --server 0 \
  --query-shard query_shards/query-to-server-0.json \
  --owner-shard owner_a_shards/owner-0-to-server-0.json \
  --owner-shard owner_b_shards/owner-1-to-server-0.json \
  --output instance/Input-P0-0
```

In the real deployment, each computation server must have a separate host and
receive only `Input-Ps-0`. Put the three public server addresses in the same
MP-SPDZ IP file on every host, and run the corresponding command on each host:

```bash
python3 -m doram_t2_3pc.run_party --server-id 0 \
  --config doram_t2_3pc/examples/config.json \
  --private-input instance/Input-P0-0 --ip-file servers.txt \
  --mpspdz-home external/MP-SPDZ --output-log server0.log
```

The per-server runner has no protocol option and invokes only
`semi-party.x`. `run_mpspdz.py` is a local end-to-end test harness only: it
launches all three parties on one machine and is not a secure non-colluding
deployment.

The client receives one log from each server and reconstructs:

```bash
python3 -m doram_t2_3pc.decode \
  --config doram_t2_3pc/examples/config.json \
  --server-log server0.log --server-log server1.log --server-log server2.log
```

Read [THREAT_MODEL.md](THREAT_MODEL.md) before interpreting any experiment.
The implementation intentionally fails on capacity overflow, unknown ontology
items, malformed/non-canonical shares, missing owners, wrong server IDs, and a
committee size other than three.

## Packed 160k-row backend

`OptimalORAM` switches to recursive Path ORAM at this scale. In the tested
MP-SPDZ version, securely initializing a 100,001-block recursive ORAM required
billions of preprocessing operations and was not practical. The supported
large-fixture path is therefore a fixed-batch packed oblivious scan:

- each five-field edge is packed into one 90-bit field element;
- owner sub-buckets remain separate and secret, preserving contribution
  hiding;
- all first-hop addresses in the public batch are evaluated in one graph scan;
- all dependent second-hop addresses are then evaluated in a second graph
  scan;
- neither addresses, relation matches, intermediate targets, nor candidates
  are opened;
- only freshly reshared top-k outputs go to the client.

This is a packed batched MPC-oblivious linear scan. Its memory trace is
independent of the secret address, but it is **O(entity_count)** rather than
sublinear and it does not implement persistent read/write ORAM state. It is a
reliable six-figure baseline, not the final asymptotic construction for a
paper.

Packed configurations must set:

```json
"field_prime": 170141183460469231731687303715884105727
```

## Opt-in relation-aware frontier compaction

Packed configurations may additionally declare an honest-owner capacity:

```json
"fanout_per_owner": 8,
"relation_fanout_per_owner": 2,
"deduplicate_terminal_answers": true
```

The first value still bounds every owner's complete outgoing bucket at one
source. The second bounds the number of records with the same
`(source, relation)` for that owner. Owner preparation validates both bounds
and fails closed; no record is truncated.

When the relation bound is smaller, the MPC circuit privately and stably
compacts first-hop relation matches before issuing dependent reads. With

```text
B = owner_count * fanout_per_owner
G = owner_count * relation_fanout_per_owner
```

the dependent scan drops from `Theta(entity_count * query_count * B^2)`
selected products to `Theta(entity_count * query_count * G * B)`, and the
candidate/top-k width drops from `B^2` to `G * B`. The first full scan and the
full graph upload are unchanged. Owner-local compaction adds
`Theta(query_count * G * fanout_per_owner)` selection cells. Match count,
matching-owner validity, original local slot, and the compacted addresses
remain secret.

Inspect the exact public circuit-shape counts before generating a program:

```bash
python3 -m doram_t2_3pc.prepare_scan estimate \
  --config config-compacted.json --query-count 10
```

When `deduplicate_terminal_answers` is enabled, the circuit retains every
candidate's terminal second-hop entity inside MPC and suppresses later paths
to an answer that has already been selected. This prevents multiple
high-scoring paths to one entity from consuming all top-k positions. The
terminal entity is not added to the output contract; the client continues to
receive only selected evidence handles and scores.

Before creating shares, each owner should audit its complete, untruncated edge
file locally:

```bash
python3 -m doram_t2_3pc.prepare_scan audit-owner \
  --config config-compacted.json --owner owner_a --edges owner_a.json
```

The report contains private degree information and should not be sent to the
servers unless the deployment intentionally makes those bounds public. Its
scope is explicitly `supplied_file_only`: a passing report proves that this
file fits the declared layout, not that an upstream dataset builder retained
every original edge. On the included three-owner ten-query fixture, setting the
total per-owner bound to two and the relation bound to one reduces the fixed
dependent frontier from six to three entries without changing its cleartext
result.

The isolated one-query local A/B run in
[`benchmarks/frontier_compaction_microbenchmark.json`](benchmarks/frontier_compaction_microbenchmark.json)
disabled answer deduplication on both variants and reconstructed identical
ranked outputs. It reduced global data from 310.488 MB to 168.269 MB and local
MPC time including preprocessing from 1.52125 s to 0.9414 s. This is evidence
for the implementation and cost model on a tiny fixture only, not a MetaQA,
WAN, or production-scale result.

This optimization is not a lossless solution for high-degree MetaQA by itself:
the source-wide `fanout_per_owner` must still cover every supplied outgoing
edge. Already-truncated fixture files cannot be repaired by the audit or the
MPC circuit.

## Planning capacity from a raw dataset

Before choosing any public bound, profile the owner's complete, untruncated
file. This command takes no public configuration precisely because a raw
dataset is profiled when it may not fit any bounds a configuration could
declare:

```bash
python3 -m doram_t2_3pc.prepare_scan plan-capacity \
  --edges raw_owner_a.json --bounded-edges capped_owner_a.json
```

It reports the source and `(source, relation)` degree distributions, what each
candidate `fanout_per_owner` would force a truncating builder to drop, the
padding cost of each candidate relation-page size, and — when a already-capped
file is supplied — the realized retained-edge fraction. The report is private
owner metadata: realized maxima are not part of the public configuration and
should not be sent to the servers unless the deployment declares them public.

## Experimental relation-paged layout

`relation_pages.py` (layout and oracle), `paged_shares.py` (sharing),
`page_program.py` (circuit), and `run_pages_mpspdz.py` (runner) are an
**experimental** backend. It compiles and executes under MP-SPDZ Semi, but the
supported backend remains the packed MPC-oblivious linear scan above: the paged
backend has been run only on one small local fixture, where it is measurably
*slower* than the scan.

It addresses the losslessness limit directly. The supported layout indexes by
`source` alone, so every bucket must reserve `fanout_per_owner` slots for the
widest source in the dataset. The paged layout indexes by `(source, relation)`
through two levels: a dense directory of `entity_count * relation_count`
descriptors, and a compact pool of `page_budget` fixed-size pages. A key
occupies `ceil(degree / page_size)` consecutive pages up to a public
`pages_per_key` bound, so high-degree keys use overflow pages instead of
forcing a global cap. Preparation fails closed on overflow; it never truncates.

Two properties matter for the circuit that will consume this layout. The
directory address `source * relation_count + (relation - 1)` is a public affine
function of two secret values, so it is computable inside MPC with one
multiplication and never opened. And because the index resolves the relation,
the per-slot secret `relation == relation_1` equality test disappears at the
first hop.

The threat model is unchanged: same three servers, same passive any-two
collusion bound, same 3-of-3 additive sharing, same secret-index linear lookup,
no new primitive and no trusted dealer. The layout does add public leakage
beyond the supported backend's bounds, and exactly this much: `page_size`,
`pages_per_key`, and the padded `page_budget`. `page_budget` is a declared
bound rather than a realized count, but it upper-bounds an owner's distinct
`(source, relation)` population and must be declared before shares exist.

Two bounds are declared and both are enforced at preparation.
`page_size * pages_per_key` is the **storage** bound for one key;
`frontier_per_owner` is the **dependent-read** bound, i.e. how many first-hop
matches per owner the circuit dereferences at the second hop. The circuit
compacts to that fixed width and never checks for overflow, so preparation must
guarantee no match is dropped — which is why exceeding either bound fails
closed. Leaving `frontier_per_owner` unset disables compaction and can never
drop an edge.

```bash
python3 -m doram_t2_3pc.prepare_pages owner \
  --config examples/ten_query/config_relation_pages.json \
  --owner owner_a --edges examples/ten_query/owner_a.json \
  --output-dir owner_a_pages

python3 -m doram_t2_3pc.prepare_pages query-batch \
  --config examples/ten_query/config_relation_pages.json \
  --queries examples/ten_query/queries.json --output-dir query_shards

python3 -m doram_t2_3pc.prepare_pages assemble \
  --config examples/ten_query/config_relation_pages.json \
  --server 0 --query-count 10 \
  --query-shard query_shards/query-batch-to-server-0.json \
  --owner-shard owner_a_pages/paged-owner-0-to-server-0.json \
  --owner-shard owner_b_pages/paged-owner-1-to-server-0.json \
  --owner-shard owner_c_pages/paged-owner-2-to-server-0.json \
  --output instance/Input-P0-0

python3 -m doram_t2_3pc.run_pages_mpspdz \
  --config examples/ten_query/config_relation_pages.json \
  --query-count 10 --instance-dir instance \
  --mpspdz-home external/MP-SPDZ --log-label paged-01
```

Use `run_pages_party` instead on three separately administered hosts, exactly
as `run_scan_party` is used for the supported backend; `run_pages_mpspdz`
centralizes all three shares and does not instantiate the non-collusion
assumption. Decode the three logs with `doram_t2_3pc.decode_batch --relation-paged`:
the output contract is unchanged, so the client side is shared with the scan
backend and only the config envelope differs.

The backend also runs through the shared regression harness, which is the only
path that exercises it on more than one query at a time:

```bash
python3 scripts/run_doram_regression.py \
  --backend relation-paged --dataset diverse --query-count 10 \
  --mpspdz-home external/MP-SPDZ --output-dir /tmp/doram-paged-regression
```

`benchmarks/relation_paged_regression.json` records that run: 10/10 distinct
queries matching the paged oracle. Running the same command with
`--backend packed-scan` and comparing the two `decoded.json` files is the
strongest end-to-end check available here — two independently implemented
backends, each validated against its own independently implemented oracle,
agreeing on every query. That comparison currently holds exactly.

To reproduce the ablation and the malicious-protocol measurements:

```bash
# One optimization at a time. These switches exist only for measurement.
python3 -m doram_t2_3pc.run_pages_mpspdz --config <layout>.json \
  --instance-dir instance --query-count 1 --mpspdz-home external/MP-SPDZ \
  --log-label abl --ablate-relation-check      # or --ablate-window-demux
                                               # or --ablate-compaction

# Same circuit, malicious protocol, same corruption threshold.
python3 -m doram_t2_3pc.run_pages_mpspdz --config <layout>.json \
  --instance-dir instance --query-count 1 --mpspdz-home external/MP-SPDZ \
  --log-label mascot --protocol-script mascot.sh --party-binary mascot-party.x
```

`--ablate-compaction` is refused unless `frontier_per_owner` already equals
`page_size * pages_per_key`, because below that width the ablated circuit would
silently drop matches rather than measure what compaction costs.

Multi-page overflow (`pages_per_key > 1`) is what makes the layout lossless for
high-degree keys, and it is the layout's most novel mechanism: one demux serves
a consecutive window, offset `j` reads the same pool shifted by `j`, trailing
dummy rows keep the shifted access in range, and a secret page count masks
pages past the end. `benchmarks/relation_paged_overflow_validation.json`
records an executed run with `pages_per_key = 2` in which all 72 supplied edges
were stored losslessly and the reconstructed result matched both cleartext
oracles exactly.

`benchmarks/relation_paged_backend_ab.json` records a measured A/B on the
ten-query fixture. Both backends returned all 10 queries in exact agreement
with two independently implemented cleartext oracles. The paged backend cost
13.9897 s and 3524.11 MB against the scan's 12.1341 s and 2798.19 MB — that is,
it was **1.15x slower and used 1.26x more communication**. This is the expected
result on this fixture, not a regression: the layout narrows a bucket from
max-source-degree to max-`(source, relation)`-degree, and in this fixture those
are 2 and 1, so the extra directory level is pure overhead. The advantage is
asymptotic and appears only where the source-wide bound would have to be large
— which is exactly the uncapped high-degree case the packed scan cannot
represent at all.

### Where the crossover is

`benchmarks/relation_paged_crossover.json` locates it. On a fixture built by
`scripts/build_skewed_fixture.py` with a narrowing factor of 8 — maximum source
degree 16, maximum `(source, relation)` degree 2 — the paged backend ran in
1.39571 s and 526.9 MB against the scan's 32.9856 s and 9218.46 MB: **23.6x
faster, 17.5x less communication**, at identical results. Read the two
benchmarks together. The paged layout is slower with no skew and wins roughly in
proportion to the narrowing factor; neither number alone describes it.

### What the 17.5x is actually made of

`benchmarks/relation_paged_ablation.json` decomposes it, because the headline
figure bundles the layout change with three circuit-level optimizations. Each
has an `ablate_*` switch on the circuit **renderer** — deliberately not on the
configuration, so no deployed layout can select one — and each variant gets its
own program name so it cannot reuse another's compiled schedule. Communication
was byte-identical across three repetitions of every arm, so the communication
ratios below are exact; wall-clock on a loaded single host is not, and its
spread is comparable to the two smaller effects.

| Optimization | Communication saved | Fixture |
| --- | --- | --- |
| Drop the redundant first-hop relation test | 1.143x | narrowing 8 |
| Share one demux across the page window | 1.072x | `pages_per_key = 2` |
| Owner-local frontier compaction | 1.740x | `slots_per_key = 4` |

Together those account for about **2.1x**. The remaining factor of about **8x**
is the layout itself, and 8 is exactly the fixture's narrowing factor. The
headline result is therefore a layout result, not a micro-optimization result.
The compaction arm is compared against a true counterfactual — the compaction
loop removed entirely, with `frontier_per_owner` widened to the full slot width
so no match is dropped — and both arms return identical rows. Rendering that
ablation is refused outright when the declared frontier is narrower than the
slot width, since aliasing there would silently discard matches. Measured
separately: the compaction machinery costs about 2.6% in communication when it
narrows nothing, so it is close to free when it does not pay.

### What the threat model costs, and how far this scales

Two measurements bound the design more sharply than any of the layout results.

**Cost is linear in the graph.** `benchmarks/relation_paged_scaling.json` varies
entity count alone and fits `data_MB = 281.3 + 0.30618 × directory_rows` with
residuals under 0.3%. Per dependent read the cost is
`Θ((1 + frontier_slots) × (entities × relations + pages))` — linear in the whole
federated graph. The paged layout improves the *constant*; it does not change
this. Extrapolated to MetaQA's 389,115 directory rows that is roughly **1.7 TB
per query** at a realistic frontier width. Batching does not rescue it: ten
queries cost 352 MB each against a single query's 370 MB, a 5% saving.

**Federation size is the worst axis.** `benchmarks/relation_paged_multiaxis.json`
moves every factor in the cost model independently rather than only entity count:

| Axis | Range tested | Scaling exponent | Verdict |
| --- | --- | --- | --- |
| graph size (`entities × relations`) | 808→6408 rows | 0.81 | linear |
| relation count | 4→16 | 0.92 | linear |
| batch size | 1→8 queries | **1.08** | linear — batching does **not** amortize |
| per-key degree | 1→4 | 1.22 | superlinear |
| **federation size (owners)** | 2→4 | **1.80** | **near-quadratic** |

Owners is close to quadratic because per-address work is proportional to the
owner count *and* the number of dependent addresses is `1 + owners × f`, also
proportional to it. A 20-owner federation costs roughly 100x a 2-owner one. That
is the axis that makes the system federated, and it is the one it handles worst.

The analytic cost model in `page_cost_estimate` was fitted on the entities,
owners, and query-count axes and validated on relations and per-key-degree,
which it had never seen: **5.25% mean, 12.4% max** held-out error. One
methodological warning is recorded with it — an earlier two-term fit on entity
count alone achieved 0.3% error and was simply wrong, underpredicting the
query-count axis by 17%, because neither training axis varied `Q`. Single-axis
validation of a multi-axis cost model is not validation.

**Efficiency.** The obliviousness overhead is **622x** — total secure products
divided by values actually needed. That is not waste to be optimized away; it is
the hiding, and it is why there is no access-pattern or volume leakage to attack.
Against a cleartext oracle the slowdown is ~7,300x. Within the protocol, the
dependent second hop plus top-k is **82.2%** of the time, so optimization effort
anywhere else is capped at 18%. Layout choice at equal semantics spans **3.07x**;
the rule is to set `page_size` to the maximum `(source, relation)` degree with
`pages_per_key = 1` when degree is uniform.

**The threat model, not the layout, is the dominant term.**
`benchmarks/threat_model_cost_fork.json` runs the identical circuit under ATLAS
(honest majority, at most **one** corrupted server) instead of Semi. The
size-independent part gets 67x cheaper; the part that grows with the graph gets
**261x** cheaper, so the observed ratio climbs from 104x to 193x across the
measured range. The same MetaQA extrapolation falls to about **6.5 GB per query**.
An independent probe on `radix_sort` shows the same effect harder — 328x — which
is why a sort-based batch join is not viable under the declared threat model but
would be under honest majority.

That is a genuine tradeoff, not a free win: two colluding servers break honest
majority completely. The declared 2-of-3 model is unusually strong for a
three-party system, and these numbers are the price of keeping it. Protocol
selection therefore goes through `protocols.py`, which **refuses** anything
weaker than the declared model unless `--allow-weaker-threat-model` is passed,
and prints a warning into the run's own output when it is.

```bash
python3 -m doram_t2_3pc.run_pages_mpspdz --config <layout>.json \
  --instance-dir instance --query-count 1 --mpspdz-home external/MP-SPDZ \
  --protocol atlas --allow-weaker-threat-model --log-label weaker-model
```

### Cost of malicious security

`benchmarks/malicious_protocol_overhead.json` records the same compiled program
and the same inputs run under `mascot-party.x` (malicious, dishonest majority)
instead of `semi-party.x` (semi-honest, dishonest majority) — the same
corruption threshold, only the adversary's behaviour changes. Both runs decoded
to results matching the cleartext oracle exactly. MASCOT cost 56.7005 s and
57496.2 MB against Semi's 1.81011 s and 369.844 MB: **31x wall-clock and 155x
communication**.

What that establishes is narrow but real: the generated circuit uses no
construct that requires passive security, and the upgrade has a measured price.
It does **not** make this system maliciously secure, and nothing here claims it
does. Both trust boundaries outside the MPC remain unauthenticated — an owner
can submit shares that reconstruct to a malformed layout, and a server can
release a wrong output share — and neither is something a protocol swap fixes.
Closing that gap needs authenticated owner input and authenticated output
release, checked in-circuit; neither is implemented. There is also still no
ideal functionality and no simulation proof, for either protocol.

```bash
python3 -m doram_t2_3pc.prepare_pages audit-owner \
  --config examples/ten_query/config_relation_pages.json \
  --owner owner_a --edges examples/ten_query/owner_a.json

python3 -m doram_t2_3pc.prepare_pages estimate \
  --config examples/ten_query/config_relation_pages.json \
  --query-count 1 --compacted-frontier-slots 4 \
  --lossless-fanout-per-owner 2089
```

`benchmarks/relation_page_cost_model.json`, regenerated by
`scripts/analyze_relation_page_layout.py`, records the analytic comparison. It
is a circuit-shape model, not a measurement, and it predates the executed runs
above; where the two disagree, the measurements win. Its one unmeasured input,
still unmeasured, is the maximum `(source, relation)`
degree of the target dataset, which is what sets `page_size`; the model flags
every assumed quantity and points at `plan-capacity` to replace it. Under the
recorded assumptions for a MetaQA-shaped graph, a packed scan wide enough to be
lossless would need `fanout_per_owner = 2089` and therefore quadratically wide
buckets, while the paged layout keeps the dependent-hop cost within a small
multiple of the current capped configuration. Treat the ratio as a design
argument for building the circuit, not as a performance result.

Prepare each owner's shards with `prepare_scan owner`. Prepare a JSON list of
one to ten queries with `prepare_scan query-batch`, then assemble each server's
file:

```bash
python3 -m doram_t2_3pc.prepare_scan owner \
  --config config-scalable.json --owner owner_a --edges owner_a.json \
  --output-dir owner_a_shards

python3 -m doram_t2_3pc.prepare_scan query-batch \
  --config config-scalable.json --queries queries.json \
  --output-dir query_shards

python3 -m doram_t2_3pc.prepare_scan assemble \
  --config config-scalable.json --server 0 --query-count 1 \
  --query-shard query_shards/query-batch-to-server-0.json \
  --owner-shard owner_a_shards/packed-owner-0-to-server-0.json \
  --owner-shard owner_b_shards/packed-owner-1-to-server-0.json \
  --owner-shard owner_c_shards/packed-owner-2-to-server-0.json \
  --output instance/Input-P0-0
```

For a local experiment:

```bash
python3 -m doram_t2_3pc.run_scan_mpspdz \
  --config config-scalable.json --query-count 1 --instance-dir instance \
  --mpspdz-home external/MP-SPDZ --log-label experiment-01
```

Use `run_scan_party` instead on three separately administered hosts. Decode
the three returned logs with `python3 -m doram_t2_3pc.decode_batch`.

A previously recorded v1 160,000-real-edge test used 100,000 real entities
plus the dummy bucket, three owners, three relations, six padded edge slots per
bucket, and one dependent two-hop query. It produced the exact cleartext
result in 43.0716 seconds on one local machine, including preprocessing.
Stage times were 0.5085 s input, 6.3140 s first oblivious scan, 0.0452 s
first-hop filtering, 34.5936 s dependent second scan, 0.9249 s
filtering/top-k, and 0.0018 s output. The important remaining limitation was
communication: 95,185.5 MB globally. Treat this as historical large-fixture
evidence for the packed scan path; the current v2 frontier-compaction circuit
still needs its own large-fixture and WAN measurements before it can support a
paper-scale scalability claim.
