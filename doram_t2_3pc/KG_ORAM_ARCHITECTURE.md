# End-to-end KG read-only ORAM architecture

The experimental `kg_oram_program.py` backend stores one independently
randomized recursive ORAM per external owner. Its logical address space is the
public dense composite key `entity * relation_count + relation - 1`; every
record contains exactly `page_size * pages_per_key` packed adjacency slots.
Absent contributions are indistinguishable all-zero records.

Inside one MPC epoch, the circuit reads every owner's first-hop record at the
secret `(source, relation_1)` address, globally compacts valid edges to the
verified public frontier, and computes each dependent address as
`secret_target * relation_count + secret_relation_2 - 1`. It then reads every
owner ORAM at that address, forms cross-owner candidates, ranks them globally,
and sends fresh output shares only to the external client.

The implementation uses a read-only per-level stash. A logical level index is
fetched from its real path at most once in an epoch. A repeat is served from
the secret stash while a fresh random dummy path is opened. `oram_epoch.py`
binds authorization to the config digest, query count, global-frontier check,
and exact per-owner access schedule. Every server atomically consumes an epoch
once. Reusing tree shares requires a new random owner construction and epoch.

Physical records are serialized row-major and recursive payloads are processed
with MP-SPDZ vectors. This matters because a position-map record carries 256
leaf labels: the earlier scalar/field-major generator exceeded 12.7 million
compiler lines on the six-figure fixture, whereas version 2 completed at about
1.5 million lines in roughly 102 seconds.

The first controlled Temi run returned an exact cross-owner two-hop result. On
the tiny fixture it used 22.50 MB versus 74.09 MB for the relation-paged Temi
control, but both measurements are distorted by minimum HE preprocessing
batches and do not predict large-scale performance. The subsequent
160,000-edge/100,000-entity execution matched all 16 oracle fields in 78.27 s
and 1.918 GB of global MPC traffic. The relation-paged Temi control was much
faster (8.77 s) but sent 2.608 GB. In addition, the ORAM epoch required 6.08 GB
of external owner shares. Thus the access path is sublinear, while fresh-state
loading is linear and currently dominates latency.

`secure_tree_shape` increases every bucket until a binary-KL Chernoff bound,
unioned over at most 64 recursion levels, bounds the statistical distance from
unconditioned uniform leaf placement by `2^-80` per owner stack. Across `n`
independently built owners the conservative distance is at most `n * 2^-80`.
This argument and its implementation need independent review; they are not a
peer-reviewed ORAM proof.

This backend is an executable end-to-end research construction, not the
selected production backend. The current security model is passive;
authorization files are operational receipts, not signatures, malicious owners
can submit malformed structures, and no crash-safe distributed secure-deletion
protocol enforces refresh. It is a bounded read-only epoch construction, not a
persistent or update-capable ORAM.
