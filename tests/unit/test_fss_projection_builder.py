import unittest

from src.aggregation.prio3_candidates import SessionCandidateHandleProvider
from src.crypto.hmac_ids import HmacIdProvider
from src.party.opaque_index_snapshot import OpaqueIndexSnapshot, ReplicatedEvaluatorIndex
from src.party.secure_index import SecurePartyIndex
from src.runtime.fss_projection_builder import OpaqueIndexProjectionBuilder


class FssProjectionBuilderTest(unittest.TestCase):
    def setUp(self):
        self.ids = HmacIdProvider(b"projection-builder-test-key")
        party = SecurePartyIndex.from_plain_graph(
            "p0",
            {"Alice": {"knows": ["Bob"]}, "Bob": {}},
            {"person": ["Alice", "Bob"]},
            self.ids,
        )
        snapshot = OpaqueIndexSnapshot.from_secure_index(party, self.ids)
        self.builder = OpaqueIndexProjectionBuilder(
            ReplicatedEvaluatorIndex((snapshot,)),
            SessionCandidateHandleProvider(b"candidate-handle-test-key", b"query-nonce-00001"),
        )

    def test_exact_entity_projection_is_global_and_padded(self):
        built = self.builder.build("entity", capacity=4)
        self.assertEqual(len(built.projection.slot_handles), 4)
        self.assertEqual(len(built.handle_to_candidate_id), 2)
        self.assertEqual(set(built.projection.point_weights), set(self.builder.index.entity_points))

    def test_type_projection_maps_type_to_member_entity_candidates(self):
        built = self.builder.build("type", capacity=4)
        type_id = self.ids.type_id("person")
        slots = built.projection.point_weights[type_id]
        candidates = {built.handle_to_candidate_id[handle] for handle in slots}
        self.assertEqual(candidates, {self.ids.entity_id("Alice"), self.ids.entity_id("Bob")})

    def test_rejects_capacity_smaller_than_global_candidate_universe(self):
        with self.assertRaisesRegex(ValueError, "smaller than candidate universe"):
            self.builder.build("entity", capacity=1)


if __name__ == "__main__":
    unittest.main()

