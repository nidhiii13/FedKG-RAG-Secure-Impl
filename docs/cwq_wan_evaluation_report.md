# CWQ Temi controlled network-sensitivity evaluation

Date: 2026-08-27. The machine-readable source for every number below is
`results/cwq_wan_temi_q10_20260827T223000Z/summary.json`.

## Scope and research question

This experiment asks how sensitive the existing three-party Temi execution is
to network delay and throughput. It reuses the fixed 10-query CWQ workload
closure, bound 8, top-k 4, three synthetic subject-hash owners, and batches of
five queries. The compiled circuit, inputs, oracle and protocol are unchanged
between profiles.

Every profile was run three times. Each repetition evaluated ten distinct
queries in two batches and checked all 160 reconstructed fields against the
independent cleartext oracle. Across the 12 main runs, all 120 query executions
and all 1,920 reconstructed fields were exact.

## Method

The direct-localhost profile uses the existing MP-SPDZ launcher. The other
profiles place an event-driven TCP proxy on every inter-party link. The proxy
adds half the configured RTT in each direction and limits each direction's TCP
payload rate. A zero-delay proxy control measures the emulator's own cost.

This is an **unprivileged userspace TCP payload emulator**, selected because
this host does not permit network namespaces, `tc netem`, or Docker. It is not
packet-level emulation and not a real three-host deployment. It does not model
TCP handshake delay, loss, jitter, kernel queueing, route variation, separate
host compute contention, or independently administered servers.

## Results

Values are medians of three repetitions. MPC time includes Temi preprocessing
and excludes compilation and share preparation. Wall time covers the complete
runner invocation for ten queries. Communication is MP-SPDZ's global total.

| Profile | Configured link | MPC s/query (range) | Runner wall, 10 q | Slowdown vs direct | Slowdown vs proxy control | Global MB/query | Exact |
|---|---|---:|---:|---:|---:|---:|---:|
| Direct localhost | native loopback | 1.822 (1.702–1.826) | 29.76 s | 1.00× | 0.64× | 198.600 | 30/30 |
| Proxy control | 0 ms, 1 Gbps | 2.863 (2.837–2.869) | 40.29 s | 1.57× | 1.00× | 198.600 | 30/30 |
| Campus | 2 ms, 1 Gbps | 8.521 (8.518–8.541) | 97.31 s | 4.68× | 2.98× | 198.600 | 30/30 |
| Regional | 20 ms, 100 Mbps | 48.946 (48.919–48.952) | 504.65 s | 26.86× | 17.10× | 198.600 | 30/30 |

Communication is identical in all runs, as expected because network conditions
do not change the circuit. The very small within-profile ranges show that the
observed increase is stable on this host. The 0 ms control also demonstrates
that userspace forwarding has material overhead; comparisons against emulated
profiles therefore report both the direct and proxy-control ratios.

## Interpretation

The current Temi circuit is strongly latency-sensitive. Even the 2 ms profile
nearly triples MPC time relative to the zero-delay proxy control. The regional
profile requires approximately 49 seconds per query amortized, despite
unchanged correctness and communication volume. Reducing interaction and
round complexity is therefore at least as important as reducing bytes for a
geographically distributed deployment.

The regional profile changes both RTT and bandwidth, so it must not be used to
claim a pure RTT coefficient. The 0 ms and 2 ms profiles hold bandwidth at
1 Gbps and provide the controlled evidence for latency sensitivity. An 80 ms
profile was not run: the 20 ms result already establishes the bottleneck, and
the expected duration would add little evidence relative to its cost.

## Defensible dissertation wording

"In a controlled userspace TCP-link emulation over three MP-SPDZ processes on
one host, the 10-query CWQ Temi closure remained exact under every tested
network profile. Median MPC time increased from 2.86 s/query with a zero-delay
proxy to 8.52 s/query at 2 ms/1 Gbps and 48.95 s/query at 20 ms/100 Mbps, while
communication remained 198.6 MB/query. These are network-sensitivity results,
not measurements from geographically distributed or independently
administered servers."

## Reproduction

```bash
PYTHONUNBUFFERED=1 .venv/bin/python -u scripts/run_cwq_wan_eval.py \
  --output results/cwq_wan_temi_q10_<timestamp> \
  --profiles localhost,proxy_control_0ms_1000mbps,campus_2ms_1000mbps,regional_20ms_100mbps \
  --repetitions 3 --batch-size 5 --runtime-timeout 3600 --compile-timeout 7200
```

The combined `summary.json`, per-repetition summaries, terminal logs, party
logs and decoded outputs are retained below the result directory. Re-running
the command with the same output directory reuses completed repetitions.
