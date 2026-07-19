import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


class PrepareMetaqaMpSpdzInputsTest(unittest.TestCase):
    def test_generates_bounded_instance_from_real_party_data(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env = os.environ.copy()
            env["FEDKG_SETUP_KEY"] = "dev-secure-test-key"
            result = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "mpspdz_client_excluded" / "scripts" / "prepare_metaqa_mpspdz_inputs.py"),
                    "--manifest",
                    str(REPO_ROOT.parent / "SimGRAG" / "configs" / "federated" / "metaqa_manifest.json"),
                    "--edge",
                    "Kismet|starred_actors|UNKNOWN",
                    "--output-dir",
                    tmpdir,
                    "--rows-per-party",
                    "16",
                    "--candidate-capacity",
                    "8",
                ],
                cwd=REPO_ROOT,
                env=env,
                check=True,
                text=True,
                capture_output=True,
            )

            payload = json.loads(result.stdout)
            self.assertEqual(payload["query"]["source"], "Kismet")
            self.assertEqual(payload["query"]["relation"], "starred_actors")
            self.assertGreaterEqual(len(payload["candidates"]), 4)
            self.assertTrue((Path(tmpdir) / "secure_kg_lookup_topk.mpc").exists())
            self.assertTrue((Path(tmpdir) / "Player-Data" / "Input-P0-0").exists())
            self.assertTrue((Path(tmpdir) / "Player-Data" / "Input-P1-0").exists())
            self.assertTrue((Path(tmpdir) / "Player-Data" / "Input-P2-0").exists())

    def test_generates_bounded_twohop_instance_from_real_party_data(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env = os.environ.copy()
            env["FEDKG_SETUP_KEY"] = "dev-secure-test-key"
            result = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "mpspdz_client_excluded" / "scripts" / "prepare_metaqa_twohop_mpspdz_inputs.py"),
                    "--manifest",
                    str(REPO_ROOT.parent / "SimGRAG" / "configs" / "federated" / "metaqa_manifest.json"),
                    "--edge",
                    "Kismet|starred_actors|UNKNOWN",
                    "--edge",
                    "UNKNOWN|starred_actors|Angel",
                    "--output-dir",
                    tmpdir,
                    "--rows-per-party",
                    "16",
                    "--path-capacity",
                    "8",
                ],
                cwd=REPO_ROOT,
                env=env,
                check=True,
                text=True,
                capture_output=True,
            )

            payload = json.loads(result.stdout)
            self.assertEqual(payload["query"]["edges"][0]["source"], "Kismet")
            self.assertEqual(payload["query"]["edges"][1]["target"], "Angel")
            self.assertGreaterEqual(len(payload["paths"]), 1)
            self.assertTrue((Path(tmpdir) / "secure_kg_twohop_lookup_topk.mpc").exists())
            self.assertTrue((Path(tmpdir) / "Player-Data" / "Input-P0-0").exists())
            self.assertTrue((Path(tmpdir) / "Player-Data" / "Input-P1-0").exists())
            self.assertTrue((Path(tmpdir) / "Player-Data" / "Input-P2-0").exists())

    def test_generates_twohop_private_topk_instance(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env = os.environ.copy()
            env["FEDKG_SETUP_KEY"] = "dev-secure-test-key"
            result = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "mpspdz_client_excluded" / "scripts" / "prepare_metaqa_twohop_mpspdz_inputs.py"),
                    "--manifest",
                    str(REPO_ROOT.parent / "SimGRAG" / "configs" / "federated" / "metaqa_manifest.json"),
                    "--edge",
                    "Kismet|starred_actors|UNKNOWN",
                    "--edge",
                    "UNKNOWN|starred_actors|Angel",
                    "--output-dir",
                    tmpdir,
                    "--rows-per-party",
                    "16",
                    "--path-capacity",
                    "8",
                    "--reveal-mode",
                    "topk",
                    "--topk",
                    "3",
                ],
                cwd=REPO_ROOT,
                env=env,
                check=True,
                text=True,
                capture_output=True,
            )

            payload = json.loads(result.stdout)
            self.assertEqual(payload["reveal_mode"], "topk")
            self.assertEqual(payload["topk"], 3)
            self.assertGreaterEqual(len(payload["paths"]), 1)
            self.assertTrue((Path(tmpdir) / "secure_kg_twohop_private_topk.mpc").exists())

    def test_semantic_relation_alias_maps_to_canonical_metaqa_relation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env = os.environ.copy()
            env["FEDKG_SETUP_KEY"] = "dev-secure-test-key"
            result = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "mpspdz_client_excluded" / "scripts" / "prepare_metaqa_twohop_mpspdz_inputs.py"),
                    "--manifest",
                    str(REPO_ROOT.parent / "SimGRAG" / "configs" / "federated" / "metaqa_manifest.json"),
                    "--edge",
                    "Kismet|acted in|UNKNOWN",
                    "--edge",
                    "UNKNOWN|acted in|Angel",
                    "--output-dir",
                    tmpdir,
                    "--rows-per-party",
                    "16",
                    "--path-capacity",
                    "8",
                    "--reveal-mode",
                    "topk",
                    "--topk",
                    "3",
                    "--semantic-relations",
                ],
                cwd=REPO_ROOT,
                env=env,
                check=True,
                text=True,
                capture_output=True,
            )

            payload = json.loads(result.stdout)
            self.assertEqual(payload["query"]["original_edges"][0]["relation"], "acted in")
            self.assertEqual(payload["query"]["edges"][0]["relation"], "starred_actors")
            self.assertEqual(payload["query"]["edges"][1]["relation"], "starred_actors")
            self.assertGreaterEqual(len(payload["paths"]), 1)

    def test_decodes_selected_topk_slot(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env = os.environ.copy()
            env["FEDKG_SETUP_KEY"] = "dev-secure-test-key"
            subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "mpspdz_client_excluded" / "scripts" / "prepare_metaqa_twohop_mpspdz_inputs.py"),
                    "--manifest",
                    str(REPO_ROOT.parent / "SimGRAG" / "configs" / "federated" / "metaqa_manifest.json"),
                    "--edge",
                    "Kismet|starred_actors|UNKNOWN",
                    "--edge",
                    "UNKNOWN|starred_actors|Angel",
                    "--output-dir",
                    tmpdir,
                    "--rows-per-party",
                    "16",
                    "--path-capacity",
                    "8",
                    "--reveal-mode",
                    "topk",
                    "--topk",
                    "3",
                ],
                cwd=REPO_ROOT,
                env=env,
                check=True,
                text=True,
                capture_output=True,
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "mpspdz_client_excluded" / "scripts" / "decode_mpspdz_topk_output.py"),
                    "--mapping",
                    str(Path(tmpdir) / "public_mapping.json"),
                    "--slot",
                    "0",
                ],
                cwd=REPO_ROOT,
                check=True,
                text=True,
                capture_output=True,
            )

            payload = json.loads(result.stdout)
            self.assertEqual(payload["selected_path_count"], 1)
            self.assertEqual(
                payload["selected_paths"][0]["edges"],
                [
                    ["Kismet", "starred_actors", "Marlene Dietrich"],
                    ["Marlene Dietrich", "starred_actors", "Angel"],
                ],
            )

    def test_generates_edge_join_instance_without_precomputed_path_rows(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env = os.environ.copy()
            env["FEDKG_SETUP_KEY"] = "dev-secure-test-key"
            result = subprocess.run(
                [
                    sys.executable,
                    str(
                        REPO_ROOT
                        / "mpspdz_client_excluded"
                        / "scripts"
                        / "prepare_metaqa_twohop_edge_join_mpspdz_inputs.py"
                    ),
                    "--manifest",
                    str(REPO_ROOT.parent / "SimGRAG" / "configs" / "federated" / "metaqa_manifest.json"),
                    "--edge",
                    "Kismet|acted in|UNKNOWN",
                    "--edge",
                    "UNKNOWN|acted in|Angel",
                    "--output-dir",
                    tmpdir,
                    "--edge-rows-per-party",
                    "16",
                    "--topk",
                    "3",
                    "--semantic-relations",
                    "--prioritize-query-rows",
                ],
                cwd=REPO_ROOT,
                env=env,
                check=True,
                text=True,
                capture_output=True,
            )

            payload = json.loads(result.stdout)
            self.assertEqual(payload["query"]["edges"][0]["relation"], "starred_actors")
            self.assertEqual(payload["total_edge_rows"], 32)
            self.assertTrue((Path(tmpdir) / "secure_kg_twohop_edge_join_topk.mpc").exists())
            self.assertTrue((Path(tmpdir) / "Player-Data" / "Input-P0-0").exists())
            self.assertTrue((Path(tmpdir) / "Player-Data" / "Input-P1-0").exists())
            self.assertTrue((Path(tmpdir) / "Player-Data" / "Input-P2-0").exists())

    def test_generates_split_edge_join_instance(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env = os.environ.copy()
            env["FEDKG_SETUP_KEY"] = "dev-secure-test-key"
            result = subprocess.run(
                [
                    sys.executable,
                    str(
                        REPO_ROOT
                        / "mpspdz_client_excluded"
                        / "scripts"
                        / "prepare_metaqa_twohop_split_edge_join_mpspdz_inputs.py"
                    ),
                    "--manifest",
                    str(REPO_ROOT.parent / "SimGRAG" / "configs" / "federated" / "metaqa_manifest.json"),
                    "--edge",
                    "Kismet|acted in|UNKNOWN",
                    "--edge",
                    "UNKNOWN|acted in|Angel",
                    "--output-dir",
                    tmpdir,
                    "--left-rows-per-party",
                    "4",
                    "--right-rows-per-party",
                    "8",
                    "--topk",
                    "3",
                    "--semantic-relations",
                    "--prioritize-query-rows",
                ],
                cwd=REPO_ROOT,
                env=env,
                check=True,
                text=True,
                capture_output=True,
            )

            payload = json.loads(result.stdout)
            self.assertEqual(payload["query"]["edges"][0]["relation"], "starred_actors")
            self.assertEqual(payload["left_total_rows"], 8)
            self.assertEqual(payload["right_total_rows"], 16)
            self.assertEqual(payload["pair_capacity"], 128)
            self.assertTrue((Path(tmpdir) / "secure_kg_twohop_split_edge_join_topk.mpc").exists())

    def test_split_edge_join_normalizes_acted_by(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env = os.environ.copy()
            env["FEDKG_SETUP_KEY"] = "dev-secure-test-key"
            result = subprocess.run(
                [
                    sys.executable,
                    str(
                        REPO_ROOT
                        / "mpspdz_client_excluded"
                        / "scripts"
                        / "prepare_metaqa_twohop_split_edge_join_mpspdz_inputs.py"
                    ),
                    "--manifest",
                    str(REPO_ROOT.parent / "SimGRAG" / "configs" / "federated" / "metaqa_manifest.json"),
                    "--edge",
                    "Stephen Furst|act in|UNKNOWN film 1",
                    "--edge",
                    "UNKNOWN film 1|acted by|Stephen Furst",
                    "--output-dir",
                    tmpdir,
                    "--left-rows-per-party",
                    "4",
                    "--right-rows-per-party",
                    "8",
                    "--semantic-relations",
                    "--prioritize-query-rows",
                ],
                cwd=REPO_ROOT,
                env=env,
                check=True,
                text=True,
                capture_output=True,
            )

            payload = json.loads(result.stdout)
            self.assertEqual(payload["query"]["edges"][1]["relation"], "starred_actors")
            self.assertEqual(payload["query"]["direction_2"], "forward")
            self.assertGreater(payload["data_parties"][0]["right_real_rows"], 0)

    def test_split_edge_join_encodes_type_edge_as_identity(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env = os.environ.copy()
            env["FEDKG_SETUP_KEY"] = "dev-secure-test-key"
            result = subprocess.run(
                [
                    sys.executable,
                    str(
                        REPO_ROOT
                        / "mpspdz_client_excluded"
                        / "scripts"
                        / "prepare_metaqa_twohop_split_edge_join_mpspdz_inputs.py"
                    ),
                    "--manifest",
                    str(REPO_ROOT.parent / "SimGRAG" / "configs" / "federated" / "metaqa_manifest.json"),
                    "--edge",
                    "Brendan Gleeson|actor of|UNKNOWN movie 1",
                    "--edge",
                    "UNKNOWN movie 1|is a|UNKNOWN",
                    "--output-dir",
                    tmpdir,
                    "--left-rows-per-party",
                    "4",
                    "--right-rows-per-party",
                    "8",
                    "--semantic-relations",
                    "--prioritize-query-rows",
                ],
                cwd=REPO_ROOT,
                env=env,
                check=True,
                text=True,
                capture_output=True,
            )

            payload = json.loads(result.stdout)
            self.assertEqual(payload["query"]["edges"][1]["relation"], "__type_identity__")
            self.assertGreater(payload["data_parties"][0]["right_real_rows"], 0)

    def test_split_edge_join_private_tables_are_query_independent(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env = os.environ.copy()
            env["FEDKG_SETUP_KEY"] = "dev-secure-test-key"
            result = subprocess.run(
                [
                    sys.executable,
                    str(
                        REPO_ROOT
                        / "mpspdz_client_excluded"
                        / "scripts"
                        / "prepare_metaqa_twohop_split_edge_join_mpspdz_inputs.py"
                    ),
                    "--manifest",
                    str(REPO_ROOT.parent / "SimGRAG" / "configs" / "federated" / "metaqa_manifest.json"),
                    "--edge",
                    "Stephen Furst|act in|UNKNOWN film 1",
                    "--edge",
                    "UNKNOWN film 1|acted by|Stephen Furst",
                    "--output-dir",
                    tmpdir,
                    "--left-rows-per-party",
                    "8",
                    "--right-rows-per-party",
                    "8",
                    "--semantic-relations",
                    "--private-tables",
                ],
                cwd=REPO_ROOT,
                env=env,
                check=True,
                text=True,
                capture_output=True,
            )

            payload = json.loads(result.stdout)
            self.assertTrue(payload["private_tables"])
            self.assertEqual(payload["data_parties"][0]["left_real_rows"], 8)
            self.assertEqual(payload["data_parties"][0]["right_real_rows"], 8)
            first_left = payload["left_tables"][0]["rows"][0]
            self.assertNotEqual(first_left.get("source"), "Stephen Furst")

    def test_e2e_slot_parser(self):
        from mpspdz_client_excluded.scripts.run_twohop_e2e import _parse_mpspdz_metrics, _parse_selected_slots

        output = """rank selected_path_slot
0 0
1 8
2 8
Time = 0.806347 seconds
Data sent = 53.154 MB in ~2935 rounds
Global data sent = 158.854 MB
"""
        self.assertEqual(_parse_selected_slots(output, sentinel=8), [0])
        self.assertEqual(
            _parse_mpspdz_metrics(output),
            {
                "mpc_time_seconds": 0.806347,
                "party0_data_mb": 53.154,
                "rounds": 2935,
                "global_data_mb": 158.854,
            },
        )


if __name__ == "__main__":
    unittest.main()
