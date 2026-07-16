import tempfile
import unittest
from pathlib import Path

from src.aggregation.prio3_candidates import SessionCandidateHandleProvider
from src.crypto.dpf import DpfKeyShare
from src.crypto.hmac_ids import HmacIdProvider
from src.orchestration.role_separated_encoded_matcher import RoleSeparatedEncodedGraphMatcher
from src.orchestration.role_separated_fss_query import RoleSeparatedFssQueryOrchestrator
from src.orchestration.role_separated_semantic_routing import RoleSeparatedSemanticRouter
from src.party.opaque_index_snapshot import OpaqueIndexSnapshot
from src.party.secure_index import SecurePartyIndex
from src.runtime.fss_evaluator_service import FssEvaluatorService, FssEvaluatorStore
from src.runtime.fss_projection_builder import OpaqueIndexProjectionBuilder
from src.runtime.opaque_index_replication import replicate_opaque_snapshots


class TwoSharePointBackend:
    def gen(self, alpha, beta, party_ids):
        return {
            party_id: DpfKeyShare(
                party_id,
                {"party": index, "alpha": alpha, "beta": beta},
            )
            for index, party_id in enumerate(party_ids)
        }

    def eval(self, key_share, point):
        return int(
            key_share.payload["party"] == 0
            and key_share.payload["alpha"] == point
        )

    def eval_many(self, key_share, points):
        return [self.eval(key_share, point) for point in points]


class RoleSeparatedSemanticGraphTest(unittest.TestCase):
    def setUp(self):
        self.ids = HmacIdProvider(b"role-separated-semantic-key")
        self.first = SecurePartyIndex.from_plain_graph(
            "p0",
            {"Kismet": {"starred_actors": ["Marlene Dietrich"]}},
            {},
            self.ids,
        )
        self.second = SecurePartyIndex.from_plain_graph(
            "p1",
            {"Marlene Dietrich": {"starred_actors": ["A Foreign Affair"]}},
            {},
            self.ids,
        )

    def _components(self):
        backend = TwoSharePointBackend()
        temporary = tempfile.TemporaryDirectory()
        snapshots = [
            OpaqueIndexSnapshot.from_secure_index(
                party,
                self.ids,
                semantic_bucket_mode="alias",
            )
            for party in (self.first, self.second)
        ]
        replicate_opaque_snapshots(snapshots, ["fss0", "fss1"], temporary.name)
        stores = [
            FssEvaluatorStore.load(Path(temporary.name) / evaluator)
            for evaluator in ("fss0", "fss1")
        ]
        lookup = RoleSeparatedFssQueryOrchestrator(
            backend,
            [FssEvaluatorService(store, backend) for store in stores],
            OpaqueIndexProjectionBuilder(
                stores[0].index,
                SessionCandidateHandleProvider(
                    b"candidate-handle-test-key",
                    b"query-nonce-00001",
                ),
            ),
        )
        semantic = RoleSeparatedSemanticRouter(
            self.ids,
            lookup,
            bucket_mode="alias",
        )
        return temporary, stores[0], lookup, semantic

    def test_semantic_snapshot_contains_hmac_bucket_mappings_without_labels(self):
        snapshot = OpaqueIndexSnapshot.from_secure_index(
            self.first,
            self.ids,
            semantic_bucket_mode="alias",
        )
        serialized = snapshot.canonical_json()
        self.assertNotIn("starred_actors", serialized)
        self.assertNotIn("Marlene Dietrich", serialized)
        self.assertTrue(snapshot.relation_bucket_index)
        self.assertTrue(snapshot.entity_bucket_index)

    def test_relation_bucket_shares_project_to_relation_candidates(self):
        temporary, _, _, semantic = self._components()
        try:
            routed = semantic.route_relations(["acted in"], capacity=4)
        finally:
            temporary.cleanup()
        relation_id = self.ids.relation_id("starred_actors")
        self.assertIn(relation_id, routed.relation_ids_by_label["acted in"])
        self.assertGreaterEqual(
            routed.relation_penalties_by_label["acted in"][relation_id],
            0.0,
        )

    def test_semantic_two_hop_path_crosses_opaque_partitions_and_builds_contributions(self):
        temporary, store, lookup, semantic = self._components()
        try:
            result = RoleSeparatedEncodedGraphMatcher(
                self.ids,
                lookup,
                store.index,
                semantic_router=semantic,
                relation_capacity=4,
                entity_capacity=8,
            ).match(
                [
                    ("Kismet", "acted in", "UNKNOWN"),
                    ("UNKNOWN", "acted in", "A Foreign Affair"),
                ]
            )
        finally:
            temporary.cleanup()

        self.assertEqual(len(result.candidates), 1)
        candidate = result.candidates[0]
        self.assertEqual(len(candidate.edges), 2)
        self.assertEqual(len(candidate.support_by_partition), 2)
        self.assertEqual(len(result.contributions), 2)
        self.assertEqual(
            {contribution.party_id for contribution in result.contributions},
            set(result.party_ids),
        )


if __name__ == "__main__":
    unittest.main()

