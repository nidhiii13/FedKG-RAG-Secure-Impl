# Recursive read-only ORAM research backend

## What is implemented

`oram_layout.py` constructs a complete owner-side recursive Path-ORAM stack:
the data tree, recursively packed position-map trees, and a small secret base.
`oram_access.py` separates owner preparation from client query preparation and
creates three-out-of-three additive shares. `oram_access_program.py` generates
an MP-SPDZ circuit that traverses the entire position-map recursion without
opening a logical address.

For each access and each recursion level, the circuit opens one leaf label and
reads the corresponding root-to-leaf path. A first read opens the block's
uniform owner-assigned leaf. If the same level index has already been read, the
value comes from a secret fixed-capacity stash and the circuit opens a fresh
uniform dummy leaf. The observable number of paths, path lengths, stash scans,
and output width depend only on the public configuration.

The owner constructs the stack locally and shares it directly. This eliminates
MP-SPDZ `RecursiveORAM.batch_init`, whose oblivious shuffle and sort dominated
the earlier experiment. It does not require a dealer or expose the owner's
permutation to a computation server.

## Executed milestone

On 21 August 2026, a three-party Temi execution read four secret addresses from
a 32-record, three-level recursive stack. The address sequence contained a
repeat: `[7, 19, 7, 31]`. Client reconstruction returned exactly
`[[1007,2007], [1019,2019], [1007,2007], [1031,2031]]`.

The run took 0.566 seconds and sent 32.378 MB globally on localhost, including
preprocessing. This number is a correctness milestone, not a performance claim:
Temi reported that its minimum preprocessing batch substantially distorted the
tiny circuit. The generated program required 338,264 bit triples, 1,912 field
triples, and 612 VM rounds.

## Security boundary

The intended model remains a static passive adversary corrupting any two of the
three Temi servers. The security argument additionally needs:

- honest owner construction and range-valid client addresses;
- fresh, independent owner leaf labels for every epoch;
- no more than the public `max_accesses` in an epoch;
- destruction or refresh of the old shares before a new circuit resets the
  stash;
- private authenticated channels for input and output shares;
- one honest server supplying entropy to MP-SPDZ's shared random generation.

Reusing the same tree shares in a later circuit with an empty stash can reveal
that a logical block repeats, because its genuine leaf would be opened again.
The implementation therefore does **not** provide persistent ORAM state or
updates. The standalone builder retains MP-SPDZ-compatible default buckets and
therefore still needs a statistical-distance analysis for its
rejection-conditioned leaf placement. The KG backend instead calls
`secure_tree_shape(..., 80)`, which increases bucket capacity until a binary-KL
Chernoff/union bound is at most `2^-80` per owner stack. That conservative bound
is implemented and tested but still needs independent proof review.

## Complexity and remaining integration

For 389,115 logical records with `chi=256`, the public cost model gives two tree
levels, a six-entry secret base, and 1,412 tree entries touched per logical read,
versus 389,115 entries for a full scan. This is sublinear **access work**.
`kg_oram_program.py` now integrates it into both hops with fixed-width
`(entity, relation)` adjacency records, contribution-hiding compaction,
dependent secret addresses, and client-only top-k. The 160k-edge execution is
exact, but all secret-shared state is still ingested at program start. That
makes total fresh-epoch setup linear even though each logical access touches a
sublinear path.

The next research milestone is amortized/persistent state loading or a hybrid
architecture that avoids uploading every tree field for each small query batch,
followed by distinct-query LAN/WAN evaluation. The present 160k result is slower
than the relation-paged baseline despite lower MPC traffic.

Do not claim a new ORAM primitive, malicious security, persistent updates, or
sublinear end-to-end epoch cost from the current milestone.
