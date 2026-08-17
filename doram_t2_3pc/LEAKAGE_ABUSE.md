# What an adversary can do with the public parameters

`IDEAL_FUNCTIONALITY.md` claims the servers' view is simulatable from the public
parameters `L = (n, E, R, k, p, m, B_1..B_n, f, g, Q)`. That claim is only reassuring
if `L` itself is harmless. This document argues it is **not** harmless, states
what it gives away, and separates the parameters that are genuinely free from the
ones that are a real disclosure.

This is deliberately written against our own design. Nothing here is a break of
the stated claim — every item is *inside* `L` by construction. The point is that
"the leakage is exactly `L`" is a weaker sentence than it sounds.

## 1. The parameters, ranked by what they disclose

| Parameter | Discloses | Severity |
| --- | --- | --- |
| `B_i` (page budget of owner `i`) | an upper bound on owner `i`'s distinct `(source, relation)` key count — essentially its data volume | **high** |
| `f` (frontier per owner) | an upper bound on the maximum per-key out-degree, per owner | medium |
| `p`, `m` (page size, pages per key) | the same degree ceiling, factored differently: `p·m` | medium |
| `E`, `R` | the size of the entity and relation universes | low — usually public schema |
| `n`, `k`, `Q` | committee size, result width, batch size | low |
| `b` (directory buckets) | a public choice, independent of the data | none |
| `s` (bucket slots) | **depends on how the keys cluster** unless set from the public bound — see §8 | low, but NOT zero |
| `g` (global frontier) | a JOINT property: federation-wide max per-key degree, hence how much participants' key sets overlap | medium, and structurally different — see §7 |

### `B_i` is the one to worry about

`B_i` is per owner and is published. It is an upper bound on how many distinct
`(source, relation)` keys owner `i` holds. In a federation of hospitals, that is
close to "how many patients with how many distinct record types this hospital
has" — a competitively and legally sensitive number, and one that ordinary MPC
intuition would expect to be hidden.

It is also **structural**: it cannot be hidden by padding *within* the current
design, because the page pool of owner `i` is a distinct region of the shared
array whose length is `B_i + m − 1`. Two colluding servers read that length off
the input file. They do not need to break anything.

## 2. Padding is the mitigation, and it is not free

The obvious fix is to publish a common `B = max_i B_i` and pad every owner's pool
to it. That restores the property that `B` says nothing about any *individual*
owner — it now only bounds the largest.

The cost is exact and measurable, because cost is linear in pool size: an owner
holding 1% of the largest owner's data pays 100x its own weight. In a federation
with one large hospital and twenty small clinics, uniform padding makes the whole
computation cost twenty-one times the large hospital, and the small clinics
shoulder cost proportional to a dataset they do not have. That is a real
disincentive to participate, which is a federation-design problem rather than a
cryptographic one.

Intermediate options, none implemented:

- **Bucketed budgets.** Publish `B_i` rounded up to a coarse ladder (say powers of
  four). Leakage drops to the bucket; cost overhead is bounded by the ladder
  ratio. Leaks less, still leaks the order of magnitude.
- **Differentially private budgets.** Publish `B_i + noise` with the noise large
  enough for a chosen `ε`. Needs the noise to be one-sided (never below the true
  requirement) or preparation fails closed, which biases it upward.
- **Owner-blind pooling.** One global pool with pages from all owners interleaved
  under a secret permutation, so no region is attributable. This removes `B_i`
  entirely, replacing it in `L` with the single federation total `Σ B_i`.

  The one-time secure setup it needs has now been **measured** rather than
  assumed: `benchmarks/volume_hiding_shuffle_cost.json` puts the pooled shuffle
  at roughly 350 GB for three owners at MetaQA scale, against about 1,710 GB for
  a single query under the declared threat model. **It amortises after 0.2
  queries** — hiding per-owner volume costs less than serving one query, which
  makes the padding alternative above strictly worse for any federation with
  unequal participants.

  Pooling moves a key's pages, so the directory descriptors pointing at them
  must be remapped, and the permutation must stay hidden from the servers or the
  pooling achieves nothing. Of the three routes, only an oblivious sort-join is
  affordable — a lookup or scatter is quadratic, around 2,377 TB. The sort-join
  has since been **measured** rather than extrapolated from a single point:
  `benchmarks/sort_join_growth.json` establishes an `n·log₂(n)` law at the key
  width the remap actually needs, correcting the earlier figure upward by 2.2x.

  Full one-time cost is therefore about **64,600 GB**, of which the shuffle is
  only 350 GB and the remap 64,274 GB. Over a 250-query epoch that is **15.1%
  per query**, not the 6.9% first estimated. Still much better than uniform
  padding for any federation with unequal participants, but the honest number is
  the larger one.

  `volume_hiding.py` implements the cleartext model and this cost model. The MPC
  circuit is not written, so no pooled deployment exists yet.

## 3. Declared bounds are not realized values, and the gap itself is informative

The bundled fixture declares `page_budget = 16` and `frontier_per_owner = 2` while
the owners actually hold 5–6 distinct keys with a maximum key degree of 1. So the
declared bounds here overstate reality by roughly 3x and 2x.

Two consequences, in opposite directions:

1. **Slack is protective.** An adversary learns the bound, not the truth. A
   generously padded bound is a genuinely weaker disclosure.
2. **Slack is expensive, so operators will minimize it.** Cost is linear in
   `B_i`, which pressures a rational operator to declare a bound just above the
   true value — at which point the bound *is* approximately the truth, and the
   protection in (1) evaporates.

This tension is the practical core of the leakage question here, and it is not
resolved by anything currently implemented. An operator who tunes for performance
is simultaneously tuning for disclosure.

## 4. What the adversary can do across a batch

`Q` is public. So is the fact that the circuit shape is identical for every query.
Two colluding servers therefore learn the number of queries but, per §4 of the
functionality, nothing distinguishing among them — there is no per-query
observable to correlate. Query-pattern leakage of the kind that afflicts
encrypted search (access-pattern and volume attacks) does **not** apply here,
precisely because every query costs the same full scan. That is the compensating
benefit of the linear design, and it should be stated alongside its cost:
the reason this is slow is the same reason it has no access-pattern leakage.

## 5. What is not analyzed

- **Repeated runs over a changing graph.** Owners re-sharing an updated `G_i`
  publish an updated `B_i`. The *sequence* `B_i(t)` leaks growth over time, which
  is more than any single `B_i`. No update protocol is implemented, so this is
  currently hypothetical, but any deployment doing refreshes inherits it.
- **Correlation with out-of-band knowledge.** An adversary who knows the domain
  may map a declared `f` or `B_i` onto specific real-world institutions. Not
  modelled.
- **The client's view.** This document concerns the servers. The client learns
  the answers, and — in the bundled fixtures — the contributing owner, via
  owner-namespaced evidence handles. See `IDEAL_FUNCTIONALITY.md` §8.
- **The honest-majority variant.** Under `--protocol atlas` a single corrupted
  server learns nothing more than described here, but *two* colluding servers
  learn everything, so this analysis does not apply to that configuration at all.

## 6. Summary

The stated leakage is real but bounded, and it is dominated by one parameter,
`B_i`. The honest framing for a write-up is:

> Access patterns and query contents are hidden; per-owner data *volume* is not.
> Hiding volume as well costs a padding factor equal to the ratio between the
> largest and smallest participant.

Claiming less than that would be overclaiming. Claiming more — for instance that
the servers learn "nothing about the owners' data" — would be false.

## 7. `global_frontier`: a joint disclosure, not a per-party one

`global_frontier` (`g`) is the one public parameter that is not a statement about
a single participant. Every other entry in `L` is declared by one owner about its
own data. `g` asserts that no `(source, relation)` key holds more than `g` edges
**summed over the whole federation**, which is a fact about the union that no
participant could have disclosed alone.

**What it gives away.** `g` is an upper bound on the federation-wide maximum
per-key degree. Combined with the per-owner bound `f`, it bounds how much the
participants' key sets *overlap*: if `g` is close to `f`, most keys are held by
roughly one owner; if `g` approaches `n·f`, many keys are held by everyone.
Overlap is competitively meaningful — it says how much of the federation's data
is redundant, and therefore how much any single participant is worth to it.

**Why it is usually still the better trade.** Without `g`, the second hop
dereferences `n·f` slots and cost is near quadratic in `n`
(`benchmarks/relation_paged_multiaxis.json`, exponent 1.80). With it, the second
hop is fixed width and the axis becomes linear
(`benchmarks/global_frontier_compaction.json`, 2.60x at six owners and growing).
A federation that cannot afford the quadratic term does not get to run at all,
and a disclosure about aggregate overlap is a much weaker one than the per-owner
volumes `B_i` already publish.

**The interaction with §2's padding argument.** Padding `B_i` to a common `B`
removes the per-owner volume leak. It does **not** remove `g`, because `g` is
about degree overlap rather than volume. The two leaks are independent and would
need separate mitigations.

**The unresolved risk is enforcement, not disclosure.** An understated `g` does
not fail closed. Owner-local bounds are checked by the owner before sharing, so
violating `f` is rejected. Nobody can check `g` alone, so an understated `g`
silently drops matches at the second hop — a correctness failure that looks like
a retrieval-quality problem rather than a bug. `check_global_frontier` catches
this offline; a deployment needs the one-time MPC pass, which is not implemented.
Treat `g` as trusted input until it is.

## 8. `b` and `s`: the compact directory adds no information, but it does add a bound

`directory_buckets` (`b`) and `bucket_slots` (`s`) exist only under the compact
directory. They are chosen by the capacity planner from the per-owner key counts
`B_1..B_n`, which §1's table already lists as public, so an adversary who reads
`b` and `s` learns nothing it could not already derive.

**CORRECTION (2026-08-17).** An earlier version of this section claimed an
adversary reading `b` and `s` "learns nothing it could not already derive." That
was wrong, and the error is worth stating plainly because it is the kind that
survives review.

`plan_capacity` sizes `s` to the **measured** worst-case bucket load. The hash is
public and data-independent, so which bucket a key lands in is fixed — but *how
many* of one owner's keys collide in the worst bucket is a property of the actual
key set. Two federations with identical `B_i` and identical `b` therefore publish
**different** `s` if their keys cluster differently. `s` is a public parameter
derived from private data, which is exactly what the leakage function is supposed
to enumerate, and it was not enumerated.

The leak is small: `s` is one integer, a maximum over every owner and every
bucket, so it identifies no owner, no bucket and no key. But "small" is not
"none," and the honest statement is that measured capacity puts a data-dependent
value in the public parameters.

**The fix, and its cost.** `public_capacity_bound` derives `s` from the public
per-owner key count and `b` alone, sized so overflow is below `2^-40` rather than
empirically absent. That value is a function of public inputs, so publishing it
reveals nothing — and it is necessarily larger than the measured maximum:

| keys per owner | `b` | measured `s` | public bound | slack measured → bound |
| --- | --- | --- | --- | --- |
| 200 | 16 | 19 | 46 | 1.52x → 3.68x |
| 5,048 | 64 | 101 | 157 | 1.28x → 1.99x |
| 156,079 | 256 | 687 | 817 | 1.13x → 1.34x |

The gap narrows as the key count grows, so at the scale where the compact layout
is worth using at all, not leaking costs about 20% extra padding. **Deployments
must use the public bound.** The measured figure is for cost analysis, where
nothing is published and the tighter number is the one you want.

**What `b * n * s` still discloses.** It upper-bounds the federation's total key
count. Under the public bound that figure is a function of `B_i` and `b`, both
public, so it is a restatement of an existing disclosure rather than a new one.

**What it does not give away.** `s` is the maximum over *all* owners and *all*
buckets, so it identifies no owner and no bucket. The hash is public and
data-independent, so bucket occupancy is not steered by any participant.

**The honest cost.** `s` is uniform, hence sized for the largest owner. A
federation with 10x volume skew pays roughly 10x the padding of a balanced one,
and that padding is visible in `b * n * s`. Under skew, the compact layout both
costs more and bounds the key count more loosely — the two effects point in
opposite directions and neither is a security failure, but a deployment on a
skewed federation should expect the layout to be a poor trade. On the datasets
measured here WebQSP's recorded split is nearly balanced (1.07x), so this cost
does not appear; it would on a realistic skewed federation.

**Not a reason to prefer the dense directory on privacy grounds.** The dense
layout leaks `E` and `R` instead, and `E * R` bounds the key count far more
loosely — but it bounds it too. Neither layout hides how much data exists; the
choice between them is a cost decision, not a privacy one.
