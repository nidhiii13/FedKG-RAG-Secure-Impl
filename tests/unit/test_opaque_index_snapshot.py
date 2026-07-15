import json
import tempfile
import unittest
from pathlib import Path

from src.crypto.hmac_ids import HmacIdProvider
from src.party.opaque_index_snapshot import OpaqueIndexSnapshot, ReplicatedEvaluatorIndex
from src.party.secure_index import SecurePartyIndex


class OpaqueIndexSnapshotTest(unittest.TestCase):
    def setUp(self):
        self.ids = HmacIdProvider(b"opaque-index-test-key")
        self.party = SecurePartyIndex.from_plain_graph(
            "hospital-a",
            {"Alice": {"knows": ["Bob"]}, "Bob": {}},
            {"person": ["Alice", "Bob"]},
            self.ids,
        )

    def test_snapshot_contains_only_encoded_index_data(self):
        snapshot = OpaqueIndexSnapshot.from_secure_index(self.party, self.ids)
        serialized = snapshot.canonical_json()

        self.assertNotIn("Alice", serialized)
        self.assertNotIn("Bob", serialized)
        self.assertNotIn("knows", serialized)
        self.assertNotIn("hospital-a", serialized)
        self.assertNotIn("display_entities", serialized)
        self.assertEqual(snapshot.entity_points, sorted(self.party.display_entities))
        self.assertEqual(snapshot.relation_points, sorted(self.party.local_relations))

    def test_snapshot_round_trip_and_digest_are_deterministic(self):
        snapshot = OpaqueIndexSnapshot.from_secure_index(self.party, self.ids)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "snapshot.json"
            snapshot.write(path)
            loaded = OpaqueIndexSnapshot.from_json(path)
        self.assertEqual(loaded, snapshot)
        self.assertEqual(loaded.digest(), snapshot.digest())

    def test_loader_rejects_plaintext_display_fields(self):
        snapshot = OpaqueIndexSnapshot.from_secure_index(self.party, self.ids)
        payload = snapshot.as_dict()
        payload["display_entities"] = {"secret": "Alice"}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text(json.dumps(payload))
            with self.assertRaisesRegex(ValueError, "forbidden"):
                OpaqueIndexSnapshot.from_json(path)

    def test_evaluator_union_preserves_opaque_partition_ownership(self):
        second = SecurePartyIndex.from_plain_graph(
            "hospital-b",
            {"Bob": {"works_at": ["Clinic"]}, "Clinic": {}},
            {},
            self.ids,
        )
        first_snapshot = OpaqueIndexSnapshot.from_secure_index(self.party, self.ids)
        second_snapshot = OpaqueIndexSnapshot.from_secure_index(second, self.ids)
        evaluator = ReplicatedEvaluatorIndex((first_snapshot, second_snapshot))

        bob_id = self.ids.entity_id("Bob")
        self.assertEqual(len(evaluator.entity_partitions(bob_id)), 2)
        self.assertIn(self.ids.relation_id("works_at"), evaluator.relation_points)


if __name__ == "__main__":
    unittest.main()

