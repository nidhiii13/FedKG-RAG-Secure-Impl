import json
import tempfile
import unittest
from pathlib import Path

from src.semantic.simgrag_embeddings import embedder_from_config, embedding_config_from_json


class SimgragEmbeddingsTest(unittest.TestCase):
    def test_loads_embedding_config_without_model_import(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "party.json"
            config_path.write_text(
                json.dumps(
                    {
                        "embedding_model": {
                            "model_path": "/tmp/local-model",
                            "device": "cpu",
                        }
                    }
                )
            )

            config = embedding_config_from_json(config_path)
            embedder = embedder_from_config(config_path)

        self.assertEqual(config["model_path"], "/tmp/local-model")
        self.assertEqual(str(embedder.model_path), "/tmp/local-model")
        self.assertEqual(embedder.device, "cpu")

    def test_cli_overrides_embedding_config(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "party.json"
            config_path.write_text(
                json.dumps(
                    {
                        "embedding_model": {
                            "model_path": "/tmp/local-model",
                            "device": "cpu",
                        }
                    }
                )
            )

            embedder = embedder_from_config(
                config_path,
                model_path="/tmp/override-model",
                device="cuda:0",
            )

        self.assertEqual(str(embedder.model_path), "/tmp/override-model")
        self.assertEqual(embedder.device, "cuda:0")


if __name__ == "__main__":
    unittest.main()
