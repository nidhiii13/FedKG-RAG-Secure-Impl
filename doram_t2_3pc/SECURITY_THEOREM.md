# Theorem statements, proof obligations, and the separation

`IDEAL_FUNCTIONALITY.md` states the functionality `F_FedKG2Hop`, the leakage
function `L`, and Definition 1 (contribution hiding), and gives an argument for
why the two-server view is simulatable. What it does not contain is a *theorem*:
a statement with quantifiers, a reduction, and an explicit list of what the
reduction assumes. This file supplies that, and is careful to distinguish the
parts that are proved from the parts that are proof obligations.

**Status.** These are written proofs at the level of a paper's body, not
machine-checked artifacts. Theorem 1 is a routine simulation argument and its
proof is complete modulo the stated assumptions. Theorem 1b gives the
statistical trace statement for the bounded KG read-only-ORAM backend, with its
additional assumptions explicit. The former Theorem 2 is retained as a
**rejected conjecture**: owner-side construction demonstrates why its original
per-read formulation is too strong.

---

## 0. Setting

Three servers `S_0, S_1, S_2`. `n` data owners `O_1..O_n`, none an MPC party. One
client `C`. A static, passive adversary `A` corrupting a set `T` of servers with
`|T| <= 2`, and optionally any subset of owners.

Shares are 3-out-of-3 additive over `F_P`. For the OT-based Semi backend,
`P = 2^127 - 1`; for Hemi/Temi, `P` is the separately audited NTT-compatible
prime `170141183460469231731687303715885907969`. Inputs are generated anew for
the selected field. All three backends are MP-SPDZ semi-honest,
dishonest-majority protocols; `Semi` remains the default and the theorem relies
on the selected backend's own security claim.

**Assumption A1 (backend).** The selected backend (`Semi`, `Hemi`, or `Temi`)
realizes the arithmetic black box `F_ABB` over `F_P` against a static passive
adversary corrupting up to two of three parties. This is assumed, not proved
here; it is the backend's own claim. The repository's protocol registry checks
the corruption classification and field compatibility but is not a proof of
the backend.

**Assumption A2 (honest inputs).** Owners and client submit well-formed shares.
The circuit range-checks every value used as an index, so a violation corrupts
results but cannot steer a read out of bounds — but `F` presumes honest input
formation, and malicious owners are out of scope.

**Assumption A3 (public parameters are data-independent).** Every element of `L`
is either a free design choice or a declared bound. Two elements need care:
`B_i` and `g` are functions of owner data, and are public *by construction* —
they are inside `L`, so disclosing them is not a violation. Under the compact
directory, `s` must be set by `public_capacity_bound`, not by the measured
maximum load, or A3 fails for `s` (see `LEAKAGE_ABUSE.md` §8). Under the
relation-partitioned residual (`rho = 1`), the same requirement applies to the
uniform per-relation capacity: `rho` is public and the relation selected during
a query remains secret. Under the
type-blocked directory, the type map `tau` must be external public input, not
derived from the federation's edges, or A3 fails for the block widths.

---

## 1. Theorem 1 (simulation security of the retrieval protocol)

**Theorem 1.** Under A1–A3, for every static passive adversary `A` corrupting
`T` with `|T| <= 2`, there is a PPT simulator `Sim` such that for all owner
databases `D_1..D_n` and all query batches `Q`,

```
    REAL_{Pi,A,T}(D, Q)   ==_c   IDEAL_{F,Sim,T}(L(D, Q))
```

where `Pi` is the protocol of `page_program`, `F` is `F_FedKG2Hop`, and `Sim`
receives only `L` — never an edge, a query, or a share.

**Proof.** By a hybrid argument over the three components of the corrupted
servers' joint view.

*Hybrid H0.* The real execution.

*Hybrid H1.* Replace every input share held by `T` with uniform elements of
`F_P`. The inputs are 3-out-of-3 additive shares, and `|T| <= 2`, so for each
shared value the adversary holds at most two shares, which are distributed
uniformly and independently of the value. The array *shapes* — directory height,
pool dimensions, query count — are functions of `L` alone. Hence `H1 == H0`
identically, not merely computationally.

*Hybrid H2.* Replace the instruction trace with one generated from `L`. The
generated circuit contains no branch on a secret and no secret-dependent memory
address: every table access is a full pass under a one-hot selector, and every
loop bound is a public constant derived from `L`. `test_ideal_functionality.py`
checks these structural properties against the generated text. Therefore the
trace is a deterministic function of `L`, and `H2 == H1`.

*Hybrid H3.* Replace the revealed outputs. The only `reveal` is
`emit_output_shares`, which for each output field draws `share_0, share_1`
uniformly and sets `share_2 = value - share_0 - share_1`; server `S_j` receives
only `share_j`. Any two of the three are uniform and independent of `value`.
Hence `H3 == H2`.

`H3` is exactly `IDEAL_{F,Sim,T}(L)` with `Sim` sampling uniform arrays of the
`L`-determined shapes, emitting the `L`-determined trace, and returning uniform
output shares — which is what `simulator.simulate_server_view` constructs. The
only computational step is A1; every other step is an identity. QED, modulo A1–A3.

**Corollary 1 (contribution hiding).** Definition 1 follows: for any two owner
databases with the same union, the views are identically distributed, because
nothing in `H3` depends on the per-owner split beyond `B_i`, which the
hypothesis holds fixed. `test_simulator.py` runs this executably by swapping two
owners' edge sets and checking that the answer is unchanged and the views are
indistinguishable.

**What Theorem 1 does *not* say.** It says the servers learn nothing beyond `L`.
It does **not** say `L` is small — `LEAKAGE_ABUSE.md` analyses what `L` gives
away, and the honest summary is bounded leakage, not zero leakage.

### Theorem 1b (bounded KG read-only-ORAM epoch)

Let `Pi_RO` be `kg_oram_program.py` with `n` independently constructed owner
stacks, statistical placement parameter `lambda`, and the public fixed access
schedule `A = Q(1 + global_frontier)` per owner. In addition to A1--A3, assume:

- **A4:** every owner honestly builds a well-formed fixed-width stack using
  independent uniform leaf labels and `secure_tree_shape(..., lambda)`;
- **A5:** a stack and its additive shares are used for exactly one authorized
  epoch of at most `A` accesses, with the in-circuit stash initially empty;
- **A6:** owners and the client use private authenticated channels to the
  corresponding server, and erased shares are not later recovered.

Then, against every static passive adversary corrupting at most two servers,
`Pi_RO` realizes `F_FedKG2Hop` with the ORAM-extended leakage in
`IDEAL_FUNCTIONALITY.md`, with distinguishing advantage at most

```
    Adv_MPC(A) + n * 2^-lambda.
```

**Proof outline.** First replace the corrupted servers' owner, query, and output
shares by uniform field elements exactly as in Theorem 1. For one owner stack,
`secure_tree_shape` assigns each recursive level a `2^-lambda / 64` failure
budget. The binary-KL Chernoff bound covers overflow of any leaf at that level;
a union bound over at most 64 levels makes rejection-conditioned placement at
most `2^-lambda` from independent unconditioned labels. A second union bound
over owners gives `n * 2^-lambda`.

In the unconditioned hybrid, a first access at a level opens an independent
uniform real leaf. If that level index repeats, the value is selected from the
secret fixed-capacity stash and the circuit opens an independent uniform dummy
leaf. The number, depth, and width of paths are fixed by the public schedule,
so the simulator samples these labels from the leakage-defined domains. All
path membership tests, recursive child selection, dependent second-address
formation, compaction, candidate construction, and top-k remain inside the
arithmetic black box. A1 replaces that computation by its simulator, and fresh
3-of-3 output sharing completes the hybrid.

This is a paper-level argument, not a machine-checked proof. A formal treatment
still has to prove the read-only stash invariant and audit correspondence
between the row-major generated circuit and the mathematical access algorithm.
The atomic marker implements A5 only for passive, correctly administered hosts;
it is not a signed or Byzantine-consistent epoch protocol. Dropping A4, A5, or
A6 is outside this theorem.

---

## 2. Former Theorem 2 (separation conjecture) — REJECTED AS STATED

The empirical result this project is most confident in is the **261x** premium
for tolerating two corrupted servers rather than one
(`benchmarks/threat_model_cost_fork.json`), together with the finding that DORAM
initialisation costs 56 billion triples at MetaQA scale under 2-of-3
(`benchmarks/doram_viability_under_dishonest_majority.json`). The natural
question is whether that gap is an artifact of the constructions tried or is
forced.

**Rejected Conjecture 2.** Let `Pi` be any three-server protocol realizing
`F_FedKG2Hop` with leakage `L` against a static passive adversary corrupting any
**two** servers, using no dealer, no trusted setup and no preprocessing
authority. Then `Pi` requires `Omega(N)` communication per dependent read, where
`N` is the size of the searchable index.

Contrast: under **one** corruption, three-server DPF/FSS-based PIR achieves
`O(sqrt(N))` or better per read, which is what GORAM's ORAM exploits on ABY3.

The owner-built read-only construction now shows why this formulation is not a
sound paper claim: owners can prepare and share correlated randomized state in
linear offline work, after which the secret-dependent path access is sublinear.
The present implementation still reloads that complete state every epoch, so
its measured end-to-end cost remains linear; that systems limitation is not a
general lower bound.

**Why it initially appeared plausible.** A sublinear oblivious read needs the servers to hold
*correlated* state that no single coalition can invert — two-server DPF keys, or
an ORAM position map replicated under honest majority. With 3-of-3 additive
sharing and two corrupted servers, any two-party correlation is entirely inside
the coalition: a DPF key pair held by `S_0, S_1` is reconstructible by
`{S_0, S_1}`, which is an admissible corruption set. This is the concrete
blockage already recorded for FSS in this project.

**Proof obligations.** To turn this into a theorem one must:

1. Formalize "searchable index" so the statement is not vacuous — a protocol may
   always pad, so the bound must be against a *correct* protocol on a database
   whose answer genuinely depends on `Omega(N)` of the input.
2. Rule out three-party correlations that survive two corruptions. This is the
   crux and it is where the conjecture could simply be **false**: replicated
   secret sharing among three parties with 2-privacy is impossible, but the
   argument must cover *any* correlated randomness, not only the schemes tried.
3. Handle preprocessing: the conjecture forbids a dealer, but two servers can
   run an offline phase between themselves, and the bound must survive that.
4. Separate the *initialization* cost from the *access* cost. The measured 56
   billion triples is an init figure, and this project also measured DORAM
   *access* as 2.65x **cheaper** than scanning — so any lower bound that proves
   access is expensive would contradict our own measurement. The conjecture must
   be about the amortized total, or about init specifically.

Obligation 4 is the one that should temper enthusiasm: our own data says the
access primitive is fine and the initialization is what is fatal. A separation
phrased about per-read cost is likely **wrong**; the defensible version is about
setup cost under 2-of-3, and that is a narrower and less quotable claim.

---

## 3. What would raise confidence

- Theorem 1 is routine and its value is mostly hygiene: it makes explicit that
  three of four hybrid steps are *identities*, so the only cryptographic
  assumption is the backend's.
- Conjecture 2 is where the intellectual content is, and obligation 2 is the one
  a reviewer will attack first. Until it is discharged, the honest phrasing is
  "no sublinear construction is known under this threshold, and the natural ones
  are blocked for a stated structural reason" — which is a *survey* claim, not a
  theorem.
