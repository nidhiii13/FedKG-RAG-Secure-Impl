# Scripts

Command-line entry points for setup, party-local indexing, query execution, and experiments.

## SimGRAG-compatible semantic embeddings

`run_private_frontier_query.py` defaults to the lightweight deterministic hashing
embedder used by unit tests. To use the same local SentenceTransformer model path
configured by SimGRAG, pass:

```bash
FEDKG_SETUP_KEY="dev-secure-test-key" python3 scripts/run_private_frontier_query.py \
  --manifest ../SimGRAG/configs/federated/metaqa_manifest.json \
  --edge 'Kismet|acted in|UNKNOWN' \
  --edge 'UNKNOWN|acted in|A Foreign Affair' \
  --semantic-relations \
  --semantic-bucket-mode hybrid \
  --embedding-backend simgrag \
  --embedding-device cpu
```

This loads `embedding_model.model_path` from the first party config in the
manifest unless `--embedding-config` or `--embedding-model-path` is supplied.
The model is loaded with `local_files_only=True`; query and party labels are
embedded only inside the trusted gateway/party-local indexing boundary. DPF/FSS
still evaluates only HMACed bucket tokens, not raw text or raw embeddings.
