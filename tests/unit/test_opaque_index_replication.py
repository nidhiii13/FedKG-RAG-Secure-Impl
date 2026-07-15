import json
import tempfile
import unittest
from pathlib import Path

from src.crypto.hmac_ids import HmacIdProvider
from src.party.opaque_index_snapshot import OpaqueIndexSnapshot
from src.party.secure_index import SecurePartyIndex
from src.runtime.opaque_index_replication import replicate_opaque_snapshots, verify_replicas


class OpaqueIndexReplicationTest(unittest.TestCase):
    def test_two_evaluators_receive_identical_plaintext_free_snapshots(self):
        ids = HmacIdProvider(b"opaque-index-test-key")
        snapshots = []
        for party_id, source, target in (("p0", "Alice", "Bob"), ("p1", "Bob", "Carol")):
            index = SecurePartyIndex.from_plain_graph(
                party_id,
                {source: {"knows": [target]}, target: {}},
                {},
                ids,
            )
            snapshots.append(OpaqueIndexSnapshot.from_secure_index(index, ids))

        with tempfile.TemporaryDirectory() as tmp:
            manifests = replicate_opaque_snapshots(snapshots, ["fss0", "fss1"], tmp)
            verify_replicas(manifests)
            first = json.loads((Path(tmp) / "fss0" / "manifest.json").read_text())
            second = json.loads((Path(tmp) / "fss1" / "manifest.json").read_text())
            first_records = [(row["partition_id"], row["digest"]) for row in first["snapshots"]]
            second_records = [(row["partition_id"], row["digest"]) for row in second["snapshots"]]
            self.assertEqual(first_records, second_records)

            snapshot_text = "".join(
                path.read_text() for path in (Path(tmp) / "fss0" / "partitions").glob("*.json")
            )
            self.assertNotIn("Alice", snapshot_text)
            self.assertNotIn("Bob", snapshot_text)
            self.assertNotIn("Carol", snapshot_text)
            self.assertNotIn("knows", snapshot_text)

    def test_rejects_non_two_evaluator_replication(self):
        with self.assertRaisesRegex(ValueError, "exactly two"):
            replicate_opaque_snapshots([], ["fss0", "fss1", "fss2"], "/tmp/not-used")


if __name__ == "__main__":
    unittest.main()

