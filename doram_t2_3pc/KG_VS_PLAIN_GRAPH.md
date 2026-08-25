# What makes this a knowledge-graph design, and not a graph design

## 0. Asymptotics, before anything else

Every layout in this document — dense, type-blocked, hashed compact, hybrid — is a
**full linear scan**. Each dependent read touches every row of its table, so all of
them are `Theta(table)` per access. What the layouts change is the *size of the
table*:

| Layout | Table size | Cost per read |
| --- | --- | --- |
| Dense | `E * R` | `Theta(E * R)` |
| Type-blocked / hashed / hybrid | roughly `O(keys)` | `Theta(keys)` |

Going from linear-in-keyspace to linear-in-data is worth 92x here and is **not**
sublinearity. No layout here has sublinear access, and the 92x must never be
described as an asymptotic improvement.

**The direction of the GORAM comparison follows from that, and it is the opposite
of what one might assume.** GORAM is an ORAM, so sublinear access is the point of
the construction, and ABY3's **honest majority** is what lets it have one. This
design tolerates two corrupted servers, which closes ORAM off:
`benchmarks/doram_viability_under_dishonest_majority.json` measures `batch_init`
at **56 billion triples** at MetaQA scale. That same benchmark found DORAM
*access* is 2.65x **cheaper** than scanning — access was never the obstacle,
initialisation was.

So:

* **GORAM** — sublinear access, tolerates **one** corrupted server.
* **This design** — linear access, tolerates **two**.

The advantage here is the corruption threshold, and losing sublinearity is what it
costs. That cost is the **261x** premium in
`benchmarks/threat_model_cost_fork.json`. Claiming sublinearity would be false and
would also discard the one differentiator that is actually established.

---

GORAM (PVLDB'25, [GORAM-ABY3](https://github.com/Fannxy/GORAM-ABY3)) is the
closest prior art, so "how is this different" has to be answered concretely
rather than by adjective. There are two independent answers. The first is the
threat model and it is already measured. The second is the data model, and it is
the one that changes the *design*.

## 1. Threat model: 1-of-3 versus 2-of-3

GORAM is built on **ABY3** (Mohassel–Rindal, CCS'18): three parties, replicated
secret sharing, **honest majority** — at most **one** corrupted server.

This project tolerates **two of three** colluding servers, which forces
dishonest-majority MPC (MP-SPDZ `Semi`/`MASCOT`) and 3-of-3 additive sharing.
That is not a tuning difference. `benchmarks/threat_model_cost_fork.json`
measures the premium at **261x** on the term that grows with the graph, and
`benchmarks/doram_viability_under_dishonest_majority.json` records that DORAM's
`batch_init` becomes 56 billion triples at MetaQA scale — which is why the
sublinear structures available to an honest-majority design are not available
here.

So a like-for-like performance comparison against GORAM is **not** meaningful
unless the corruption threshold is stated with it. Any table that puts the two
side by side without that column is misleading, in our favour or theirs.

## 2. Data model: the relation dimension is both the problem and the fix

A plain graph has one untyped adjacency. A knowledge graph's adjacency is a
**3-tensor** `entity x relation x entity`, and that third dimension is exactly
what makes this project expensive: the directory is dense in
`entity_count x relation_count`, which is 771,502,600 rows on WebQSP at
**0.154% occupancy** (`benchmarks/webqsp_smoke.json`).

The important observation is that the padding is not uniformly meaningless.
Most `(entity, relation)` pairs are not *absent from the data* — they are
**impossible under the ontology**. `film.actor.film` cannot originate at a film,
a city or a date; only at an actor. And an ontology is **public**.

That gives a reduction with no privacy cost at all: drop every row whose entity
cannot carry that relation. Nothing secret is removed, because which rows are
type-valid is a function of the published schema, not of any owner's edges.

**A plain graph has no such structure.** Untyped edges have no domain, so there
is no publicly-known sparsity to exploit. This reduction exists *only* for
knowledge graphs, and it attacks precisely the term that the relation dimension
introduced.

### Measured on real WebQSP

`scripts/measure_type_blocking.py`:

| | |
| --- | --- |
| entities | 203,027 |
| relations | 3,800 |
| distinct relation domains | 1,797 |
| dense directory rows | 771,502,600 |
| **type-blocked rows** | **5,785,620** (133x fewer) |
| widest relation block | 57,018 (4x narrower than `E`) |
| modelled products, dense-folded | 1,546,050,605 |
| ~~modelled products, type-blocked~~ | ~~12,426,510 (124x)~~ **WITHDRAWN — see §2b: this row count is not addressable** |

An earlier version of this document claimed type-blocking beat the hashed compact
directory by ~2.5x. **That comparison was invalid** -- see §2b. Corrected, hashing
wins on full-coverage cost. Type-blocking would still avoid all of: no key tags to store, no tag comparison per fetched slot, no
capacity planning, no overflow risk, no in-circuit hash, and no new public
parameter beyond the ontology itself.

## 2b. CORRECTION (2026-08-17): the 133x is not addressable

The 133x above counts the rows of the **covering** layout -- every entity present
in the block of every relation whose domain it admits. Implementing it revealed
that this layout **cannot use the cheap addressing** described in §3, and the
error is worth recording in full because it inverted a recommendation.

Affine addressing needs a relation's admissible entities to be a **contiguous
range** of entity ids, so that `address = c_r + entity`. That requires a
*partition* of entities into types. But a Freebase entity carries **1 to 189**
domains (median 2), so the admissible sets **overlap** and no single entity
ordering makes them all contiguous. In the covering layout an entity's position
inside a block is its *rank among that domain's members*, which is a different
function per relation and is not affine in the entity id. Recovering it in circuit
would need a lookup table of size `relation_count * entity_count` -- the dense
directory again.

Four variants were measured on real WebQSP. Only the last three are addressable:

| Variant | Rows | vs dense | Edge coverage | Affine? |
| --- | --- | --- | --- | --- |
| Covering | 5,785,620 | 133x | 100% | **no** |
| Partition (primary type) | 3,842,291 | 201x | **54.1%** | yes |
| Bounding interval (best of 4 orderings) | 101,384,453 | 8x | 100% | yes |
| Layered intervals, L=2 | 279,886,766 | 3x | 73.8% | yes |

**Layering does not rescue it.** Splitting each entity's domains into layers, one
partition per layer, reproduces the covering row count *exactly* (verified:
sum over layers = 5,785,620) and each layer is individually a partition. But the
entity ids are global and shared across layers, so at most one layer can be
exactly contiguous; the rest fall back to bounding intervals and collapse --
layer 2 alone costs 276M rows because entities sharing a second domain are
scattered through the layer-1 ordering.

### What this means for the layout choice

Modelled products at full WebQSP scale, 16 addresses, folded where applicable:

| Layout | Products | vs dense | Coverage | Needs ontology | Data-dependent public parameter |
| --- | --- | --- | --- | --- | --- |
| Dense, folded (current) | 1,546M | 1x | 100% | no | no |
| Type-blocked, bounding interval | 205M | 7.5x | 100% | yes | no |
| **Hashed compact** | **30.7M** | **50x** | **100%** | **no** | `s`, unless `public_capacity_bound` |
| Type-blocked, partition | 8.3M | 186x | **54%** | yes | no |

**The hashed compact directory is the best full-coverage option, and the earlier
recommendation to retire it in its favour was wrong.** Hashing does not need
contiguity -- that is precisely what the hash buys -- so it reaches the
"size to the data" goal that type-blocking can only reach by dropping edges. The
comparison that produced the wrong answer priced type-blocking's *covering* rows,
which no circuit can address, against hashing's *real* cost.

### The variant worth building

Neither alone. **Type-blocked partition for the 54% of edges whose domain is the
entity's primary type, plus a hashed compact table for the 46% residual.** The
partition half is affine and nearly free; the hashed half carries only the
residual keys, so its per-slot comparison is paid on ~360k keys instead of 780k.
Modelled at roughly 22M products, **~70x**, with full coverage. Not implemented
and not measured; the number is arithmetic on the two component models.

## 3. Relation-paged directory v2, concretely

The current layout puts `(entity, relation)` at dense address
`entity * relation_count + relation - 1`. v2 replaces that with a concatenation
of per-relation blocks, where a relation's block spans only the entities its
domain admits.

**Public inputs** (both from the published ontology, alongside the existing
entity and relation vocabularies):

- `tau : entity -> type`
- `dom : relation -> type`

**Layout.**

1. Renumber entities so each type class is contiguous: type `t` occupies
   `[start_t, start_t + n_t)`.
2. Relation `r` owns a block of width `n_dom(r)` at public offset
   `off_r = sum over r' < r of n_dom(r')`.
3. The row for `(e, r)` exists iff `tau(e) = dom(r)`, at index
   `off_r + (e - start_dom(r))`.

**Addressing, in circuit.** The address is

```
address = c_r + e          where c_r = off_r - start_dom(r)
```

`c_r` is a public table read at a **secret** `r`, so it costs one demux over
`relation_count` — cheap, and `relation_count` is tiny beside the directory.
After that the address is *affine* in the secret entity, so it costs no
multiplication, exactly as the current dense address does. The same demux
returns `start_dom(r)` and `n_dom(r)` for the range check that gates an entity
outside the block to the dummy row.

**Hop two still folds.** Every hop-two address shares `relation_2`
(`benchmarks/relation_folded_directory.json`), so the table is contracted to
`relation_2`'s block once — cost `sum_r n_dom(r)`, the whole table — and each of
the frontier addresses then reads a block padded to `max_r n_dom(r)`:

```
hop1  =  sum_r n_dom(r)
hop2  =  sum_r n_dom(r)  +  frontier * max_r n_dom(r)
```

against the current `E*R + E*R + frontier * E`. Both terms shrink: the table by
133x and the per-address term by 4x.

**The range constraint is free.** A hop-two intermediate that cannot carry
`relation_2` has no row in that block, so it is gated to the dummy without a
single extra comparison. Under the dense layout that entity still consumed a
full row.

### Executable lossless hybrid

The strict partition above cannot cover multi-domain entities by itself. The
executable opt-in path therefore reads two tables on every access: the affine
primary-type block and a hashed residual containing every key outside that
primary type. At most one descriptor is non-zero, so their sum is the desired
descriptor and the trace does not reveal which half supplied it. Owner
preparation fails closed on either table's capacity.

`benchmarks/hybrid_directory_execution.json` records a one-query MP-SPDZ Semi
run with exact agreement on all 16 output fields. This closes the earlier
"model-only" implementation gap on a small fixture. Batched residual-tag
decomposition now lets all ten distinct fixture queries compile and match all
160 oracle fields. It does not validate the modelled WebQSP ratio: compilation
still processes roughly 4.2 million lines, so compiler expansion remains a
scaling concern.

## 4. What is NOT established

- **The large-scale v2 projection is not executed.** Only the small lossless
  hybrid above has run in MPC. The full-WebQSP ratio remains a modelled product
  count, not measured bytes or latency.
- **The 133x is an upper bound.** The measurement derives entity types from the
  relations each entity is *observed* to carry, which is owner data. A genuinely
  public type map also contains entities with no observed edges of that type,
  widening every block and lowering the gain. Quantifying that needs the
  Freebase type assertions, which this fixture does not ship.
- **The public type map is a new public input.** It is not a trusted dealer, a
  trusted setup, or owner-side aggregation, and it says nothing about which edges
  exist — but it is one more thing the servers see, and a deployment whose
  ontology is itself sensitive cannot use this.
- **Multi-typed entities are handled but cost more.** An entity with `k` types
  appears in the blocks of every relation whose domain it matches; on WebQSP most
  entities carry 1–6 domains, and `sum_r n_dom(r)` already includes that.
- **It does not make the design practical.** 12.4M products per query at full
  WebQSP scale is 124x better and still far above any usable per-query cost.
  This narrows a gap of five orders of magnitude to three.
- **Exploiting labels is not itself new.** Structured encryption has used
  labelled-graph structure since Chase–Kamara (Asiacrypt'10). What is plausibly
  new here is doing it inside a **2-of-3 dishonest-majority MPC index** with the
  reduction measured on a real federated KG — and that claim needs checking
  against the structured-encryption literature before it is made in a paper.
