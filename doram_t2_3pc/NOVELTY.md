# Novelty adjudication

A claim-by-claim assessment of what in this implementation is new, what is
standard, and what has direct prior art. Written to be usable as the "why this
is not already known" section of a paper — or as the reason not to write one.

**Verification status.** Prior-art positions below were verified against the
primary sources during earlier review passes on this project; they have not been
re-verified in the current pass, and no new literature search was run. Assistant
knowledge cut-off is May 2026. Anything published after that is not covered.
Items marked *assessment* are architectural judgement, not a literature finding.

## 1. The mechanisms, enumerated

Taken from the implementation, not from the framing:

| # | Mechanism | Where |
| --- | --- | --- |
| M1 | Two-level index: `directory[source × R + relation − 1]` → page descriptor → page pool | `relation_pages.py`, `page_program.py` |
| M2 | Directory address affine in two secrets, so addressing needs no secret×secret multiply | `directory_address()` |
| M3 | Descriptor packs `(page_base, page_count)`, range-clamped to a dummy page | `unpack_descriptor()` |
| M4 | Shifted-window read: one demux serves `pages_per_key` consecutive pages, tail-padded pool, secret page count masks the overhang | `read_page_window()` |
| M5 | Owner-local frontier compaction to a fixed width | compaction loop |
| M6 | Declared bounds enforced fail-closed at preparation, making M5 lossless | `build_owner_page_layout()` |
| M7 | Edge packed into one field element (`target‖relation‖evidence‖score‖valid`) | `packed.py` |
| M8 | Client-only reconstruction via fresh full-field masks | `emit_output_shares()` |

## 2. Adjudication

### M1 — two-level relation-resolved index · **NOT NOVEL**

Closest prior art: Keller & Scholl, *Efficient, Oblivious Data Structures for
MPC* (ASIACRYPT 2014). That work builds oblivious arrays, dictionaries keyed by
secret-shared keys, and — directly relevant — a graph representation as an index
array of first-neighbour pointers into an edge list, used for oblivious Dijkstra
and BFS. That is structurally the same index→block indirection, under a
**stronger** (malicious, dishonest-majority) model.

This is not a distant analogy. The same construction ships inside this
repository's own MP-SPDZ checkout as `Programs/Source/dijkstra_example.mpc`,
which builds `e_index` and `edges` as two `OptimalORAM` instances — index into
edge list, exactly M1's shape.

The refinement here is keying on the composite `(source, relation)` rather than
`source` alone. In database terms that is a composite index, and choosing a more
selective key is textbook. The *measured consequence* of that choice — the
narrowing factor, worth 17.5× on a skewed fixture — is a legitimate empirical
result. The mechanism is not new.

### M2 — affine secret addressing · **STANDARD**

`source × R + relation − 1` with `R` public is a linear combination of secrets
with public coefficients, free in any linear secret-sharing scheme. Standard
technique, correctly applied.

### M3 — descriptor packing and range clamping · **STANDARD**

Defensive engineering. Good practice; not a contribution.

### M4 — shifted-window read · **MINOR** *(assessment)*

One selector reused across `pages_per_key` consecutive offsets, with
`pool_rows = page_budget + pages_per_key − 1` tail padding so every shifted
access stays in range, and a secret page count zeroing the overhang.

This is a competent optimization and is the least standard item in the list. It
is also the smallest: measured at **1.072×** communication
(`benchmarks/relation_paged_ablation.json`), and only observable at all when
`pages_per_key > 1`. Reading a contiguous block through a single index is a
natural construction, and no claim of novelty should rest on it.

### M5 — owner-local compaction for contribution hiding · **MODEST, AND THE STRONGEST ITEM**

Oblivious compaction itself is classical. What is defensible here is the
*reason* it is present, and it is worth stating precisely because it is easy to
get wrong:

The design keeps each owner's records in a **separate region** of the shared
arrays. That is a deliberate deployment property — every owner prepares and
deals its own shares independently, with no joint setup, no trusted dealer, and
no owner needing to see another's data. But separation creates a leak that a
single merged array would not have: the number of *occupied* slots in owner `i`'s
region would reveal how many matches owner `i` contributed.

Fixed-width compaction closes exactly that leak. Every owner always emits `f`
slots; occupancy rides in secret validity bits. An owner contributing nothing and
an owner contributing `f` produce identical traces.

So the contribution is a *composition*: independent per-owner preparation, which
is what makes the federated deployment story work, plus compaction, which repairs
the leakage that independence introduces. Neither half is new. The pairing, in
service of a federated threat model where owners are not MPC parties, is the one
place this design says something a generic oblivious-graph paper does not.

Two caveats that materially limit even this:

1. It is a property **against the servers only**. In the bundled fixtures the
   client can read the contributing owner straight off the evidence handle.
   See `IDEAL_FUNCTIONALITY.md` §8.
2. Per-owner data *volume* still leaks, via the public page budget `B_i`.
   See `LEAKAGE_ABUSE.md`.

### M6 — fail-closed declared bounds · **ENGINEERING**

Necessary for M5's losslessness — without it, compaction to a fixed width
silently drops matches — and correctly implemented. Discipline, not novelty.

### M7, M8 — bit-packing, masked output resharing · **STANDARD**

## 3. What is left

No primitive-level novelty. One modest composition-level idea (M5). A systems
result that is a constant-factor improvement whose magnitude equals the
narrowing factor of the dataset.

Against the closest systems prior art — GORAM (PVLDB 2025) for oblivious graph
queries, and the oblivious-analytics line (Secrecy NSDI 2023, ORQ SOSP 2025) —
this implementation is smaller in scale and weaker in formalization, and its
distinguishing feature is the federated leakage profile rather than the data
structure.

## 4. The strongest asset is not the construction

On the evidence gathered, the most defensible publishable result here is
**measurement, not mechanism**:

`benchmarks/threat_model_cost_fork.json` shows that holding the circuit fixed and
moving from any-2-of-3 collusion to at-most-1-of-3 buys **261×** on the term that
grows with the graph — more than ten times what the layout optimization
(17.5×) buys. `benchmarks/relation_paged_ablation.json` separates the layout
effect (~8×) from the circuit micro-optimizations (~2.1×) rather than reporting
one bundled number. `benchmarks/relation_paged_scaling.json` establishes the
growth law, and the multi-axis validation shows the analytic cost model predicts
measured communication to within a few percent across independent axes.

"What does the dishonest-majority assumption actually cost for oblivious
multi-hop graph retrieval, and how much of a reported speedup is layout versus
micro-optimization" is a question with a real answer here, backed by executed
runs, negative results retained, and an ablation that resists over-attribution.
That is an evaluation contribution. It is a weaker claim than a new construction,
and it is much better supported by what exists.

## 5. What would create genuine novelty

Ranked by how much they would move the assessment, not by effort:

1. **Formalize and prove the federated contribution-hiding property** (M5) as a
   definition other work can be measured against, including the client-side
   scope caveat. Today it is an implementation detail with a benchmark.
2. **Remove the `B_i` volume leak** without uniform padding — bucketed or
   noised budgets with a stated privacy parameter, or owner-blind pooling under
   a one-time secure setup. This is an open problem with a concrete cost metric
   already in place, which is a good position to attack it from.
3. **Authenticated owner input**, making the MASCOT result an end-to-end
   malicious-security claim rather than a protocol-swap measurement.
4. **Sublinear dependent reads under 2-of-3 collusion**, or a proof that the
   linear bound is inherent for this corruption threshold. The latter would be
   the strongest possible outcome: it converts the project's central limitation
   into its central theorem.

Item 4 is the one that would change the venue. The measurements already show the
linear cost is not an artifact of the layout; showing it is *necessary* under
this threat model would be a real result, and the failed sorting probe
(`threat_model_cost_fork.json`) is evidence toward it rather than against it.
