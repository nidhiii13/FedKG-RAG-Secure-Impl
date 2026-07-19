import json
import os
import pickle
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = REPO_ROOT / "mpspdz_client_excluded" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from bucketed_oram_index import (  # noqa: E402
    build_party_index,
    directory_slot,
    probe_slots,
    write_party_index,
)
from prepare_metaqa_mpspdz_inputs import _hmac_int  # noqa: E402


class BucketedOramIndexTest(unittest.TestCase):
    def test_directory_resolves_query_to_compact_adjacency_block(self):
        key = "test-key"
        graph = {"Kismet": {"starred_actors": ["Marlene Dietrich"]}}
        index = build_party_index(
            graph,
            key,
            allowed_relations={"starred_actors"},
            read_padding=4,
        )
        source_id = _hmac_int(key, "entity", "Kismet")
        relation_id = _hmac_int(key, "relation", "starred_actors")
        capacity = len(index["source_directory"])
        base = directory_slot(key, "source", 0, source_id, relation_id, capacity)

        entry = None
        for slot in probe_slots(base, capacity, index["stats"]["source_probe_limit"]):
            candidate = index["source_directory"][slot]
            if candidate[5] and candidate[:3] == (source_id, relation_id, 0):
                entry = candidate
                break
        self.assertIsNotNone(entry)
        offset, count = entry[3], entry[4]
        self.assertEqual(count, 1)
        edge = index["source_edges"][offset]
        self.assertEqual(edge[0], source_id)
        self.assertEqual(edge[2], _hmac_int(key, "entity", "Marlene Dietrich"))
        self.assertIn(str(edge[3]), index["evidence_vault"])

    def test_prepares_query_without_embedding_party_rows_in_public_mapping(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            key = "test-key"
            graphs = [
                {"Kismet": {"starred_actors": ["Marlene Dietrich"]}},
                {"Marlene Dietrich": {"starred_actors": ["Angel"]}},
            ]
            initial = [
                build_party_index(
                    graph,
                    key,
                    allowed_relations={"starred_actors"},
                    read_padding=4,
                )
                for graph in graphs
            ]
            capacity = max(
                max(len(index["source_directory"]), len(index["target_directory"]))
                for index in initial
            )
            indexes = [
                build_party_index(
                    graph,
                    key,
                    allowed_relations={"starred_actors"},
                    source_directory_capacity=capacity,
                    target_directory_capacity=capacity,
                    read_padding=4,
                )
                for graph in graphs
            ]
            index_root = root / "indexes"
            party_entries = []
            summaries = []
            for number, (graph, index) in enumerate(zip(graphs, indexes)):
                party_id = f"party_{number}"
                data_path = root / f"{party_id}.pkl"
                with data_path.open("wb") as handle:
                    pickle.dump({"graph": graph}, handle)
                party_entries.append({"party_id": party_id, "data": str(data_path)})
                write_party_index(index, index_root / party_id)
                summaries.append({"party_id": party_id, **index["stats"]})
            (index_root / "metadata.json").write_text(
                json.dumps(
                    {
                        "format": "fedkg-mpspdz-oram-index-set-v1",
                        "relations": ["starred_actors"],
                        "parties": summaries,
                        "directory_capacity": capacity,
                        "max_candidates": 4,
                    }
                )
            )
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps({"parties": party_entries}))
            instance = root / "instance"
            env = os.environ.copy()
            env["FEDKG_SETUP_KEY"] = key
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS / "prepare_metaqa_twohop_oram_mpspdz_inputs.py"),
                    "--manifest",
                    str(manifest_path),
                    "--index-dir",
                    str(index_root),
                    "--edge",
                    "Kismet|starred_actors|UNKNOWN",
                    "--edge",
                    "UNKNOWN|starred_actors|Angel",
                    "--output-dir",
                    str(instance),
                    "--max-candidates",
                    "4",
                    "--topk",
                    "2",
                ],
                cwd=REPO_ROOT,
                env=env,
                check=True,
                text=True,
                capture_output=True,
            )
            payload = json.loads(result.stdout)
            gateway_receipt = json.loads((instance / "query_gateway_receipt.json").read_text())
            self.assertEqual(payload["query"]["edges"][0]["source"], "Kismet")
            self.assertNotIn("left_tables", gateway_receipt)
            self.assertNotIn("right_tables", gateway_receipt)
            self.assertFalse((instance / "public_mapping.json").exists())
            self.assertTrue((instance / "secure_kg_twohop_oram_join_topk.mpc").exists())
            self.assertTrue((instance / "Player-Data" / "Input-P2-0").exists())

            if os.environ.get("RUN_MPSPDZ_INTEGRATION") == "1":
                run_env = env.copy()
                run_env["MP_SPDZ_HOME"] = str(REPO_ROOT / "external" / "MP-SPDZ")
                mpc = subprocess.run(
                    [
                        "bash",
                        str(SCRIPTS / "run_mpspdz_oram_instance.sh"),
                        str(instance),
                    ],
                    cwd=REPO_ROOT,
                    env=run_env,
                    check=True,
                    text=True,
                    capture_output=True,
                )
                raw_output = instance / "mp_spdz_output.txt"
                raw_output.write_text(mpc.stdout)
                decoded = subprocess.run(
                    [
                        sys.executable,
                        str(SCRIPTS / "decode_mpspdz_oram_output.py"),
                        "--mapping",
                        str(instance / "query_gateway_receipt.json"),
                        "--mp-spdz-output",
                        str(raw_output),
                    ],
                    cwd=REPO_ROOT,
                    check=True,
                    text=True,
                    capture_output=True,
                )
                reveal = json.loads(decoded.stdout)
                self.assertEqual(reveal["selected_path_count"], 1)
                self.assertEqual(
                    reveal["selected_paths"][0]["edges"],
                    [
                        ["Kismet", "starred_actors", "Marlene Dietrich"],
                        ["Marlene Dietrich", "starred_actors", "Angel"],
                    ],
                )


if __name__ == "__main__":
    unittest.main()
