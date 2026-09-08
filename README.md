# Privacy-Preserving Federated Knowledge-Graph Retrieval

This repository implements structured, relation-dependent two-hop retrieval
over knowledge graphs contributed by multiple data owners. Owners and the query
client provide three-out-of-three additive shares to a fixed committee of three
MP-SPDZ servers. The principal relation-paged backend performs both dependent
lookups, frontier compaction, global top-k ranking, and fresh output resharing
without opening the query, intermediate entity, owner records, or plaintext
result to the computation servers under the stated passive threat model.

The implementation is a research prototype. Its threat model, public leakage,
and unsupported guarantees are specified in
[`doram_t2_3pc/THREAT_MODEL.md`](doram_t2_3pc/THREAT_MODEL.md) and
[`doram_t2_3pc/IDEAL_FUNCTIONALITY.md`](doram_t2_3pc/IDEAL_FUNCTIONALITY.md).

## Setup

Clone the pinned cryptographic dependencies and create a Python environment:

```bash
git clone --recurse-submodules https://github.com/nidhiii13/FedKG-RAG-Secure-Impl.git
cd FedKG-RAG-Secure-Impl
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

MP-SPDZ and the optional PIR/FSS baselines have their own native build
requirements. Follow the upstream build instructions in each submodule before
running the corresponding backend.

## Verification

Run the project tests and verify the report-facing result summaries with:

```bash
python3 -m pytest -q
python3 scripts/verify_cwq_report.py
```

The relation-paged implementation and protocol documentation are under
[`doram_t2_3pc/`](doram_t2_3pc/), while experiment entry points and their
dataset-specific boundaries are described in
[`scripts/README.md`](scripts/README.md).

## Repository layout

- `doram_t2_3pc/`: secure retrieval implementation, protocol documentation,
  fixtures, and preserved benchmark summaries.
- `scripts/`: dataset preparation, experiment orchestration, and report-result
  verification.
- `tests/`: unit and integration tests.
- `data/`: small prepared metadata and fixtures that can be redistributed.
- `results/`: selected machine-readable summaries used by the report. Large
  generated MPC instances, private-input files, and raw datasets are excluded.
- `mpspdz_client_excluded/`, `multiparty_fss/`, `src/`, and `tools/`: baseline
  and supporting implementations retained for comparison.

## Setup

Clone the pinned external dependencies and install the Python requirements:

```bash
git clone --recurse-submodules <repository-url>
cd FedKG-RAG-Secure-Impl
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

MP-SPDZ must be built for the required protocol before native MPC experiments
are run. See [`doram_t2_3pc/README.md`](doram_t2_3pc/README.md) and
[`scripts/README.md`](scripts/README.md) for the protocol-specific workflows.

## Verification

The following checks validate the Python sources, run the project tests, and
verify the principal values quoted in the report against the preserved result
summaries:

```bash
python3 -m compileall -q src scripts tests
python3 -m pytest -q
python3 scripts/verify_cwq_report.py
```

The verifier covers the reported CWQ retrieval and generation results, native
Temi correctness workloads, network experiment, the completed 1,000-question
domain-scoped CWQ run, and the completed 500-question MetaQA run.

## Data and generated artefacts

Raw CWQ, RoG-CWQ, KQA Pro, and MetaQA inputs are not redistributed here.
Dataset preparation commands and provenance notes are documented in
[`scripts/README.md`](scripts/README.md). Generated secret shares, MP-SPDZ
instances, compilation products, and full execution logs are intentionally
ignored because they are reproducible, large, or may contain experiment-local
paths. Only the compact summaries needed to audit the reported measurements
are versioned.
