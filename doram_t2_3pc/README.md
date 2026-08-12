# Three-server semi-honest DORAM prototype

This directory is a clean implementation path for two-hop federated KG
retrieval with a fixed three-server MPC committee. It does not reuse the old
design in which the query gateway and data owners are MP-SPDZ players.

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

This construction is genuine DORAM in the sense that its memory trace is
independent of the secret address, but it is **O(entity_count)** rather than
sublinear. It is a reliable six-figure baseline, not the final asymptotic
construction for a paper.

Packed configurations must set:

```json
"field_prime": 170141183460469231731687303715884105727
```

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

The reproducible 160,000-real-edge test used 100,000 real entities plus the
dummy bucket, three owners, three relations, six padded edge slots per bucket,
and one dependent two-hop query. It produced the exact cleartext result in
43.0716 seconds on one local machine, including preprocessing. Stage times
were 0.5085 s input, 6.3140 s first DORAM scan, 0.0452 s first-hop filtering,
34.5936 s dependent second scan, 0.9249 s filtering/top-k, and 0.0018 s output.
The important remaining limitation is communication: 95,185.5 MB globally.
Thus this backend removes the timeout and establishes correctness at 160k,
but a DPF/FSS or other sublinear-access construction is still needed for a
WAN-practical tier-1 system.
