import tempfile
import unittest
from pathlib import Path

from src.aggregation.prio3_candidates import SessionCandidateHandleProvider
from src.crypto.dpf import DpfKeyShare
from src.crypto.hmac_ids import HmacIdProvider
from src.orchestration.role_separated_fss_query import RoleSeparatedFssQueryOrchestrator
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


class RoleSeparatedFssQueryOrchestratorTest(unittest.TestCase):
    def test_exact_query_returns_candidate_without_exposing_matched_point_response(self):
        ids = HmacIdProvider(b"role-separated-query-key")
        party = SecurePartyIndex.from_plain_graph(
            "p0",
            {"Alice": {"knows": ["Bob"]}, "Bob": {}},
            {},
            ids,
        )
        snapshot = OpaqueIndexSnapshot.from_secure_index(party, ids)
        backend = TwoSharePointBackend()
        with tempfile.TemporaryDirectory() as tmp:
            replicate_opaque_snapshots([snapshot], ["fss0", "fss1"], tmp)
            services = [
                FssEvaluatorService(FssEvaluatorStore.load(Path(tmp) / evaluator), backend)
                for evaluator in ("fss0", "fss1")
            ]
            orchestrator = RoleSeparatedFssQueryOrchestrator(
                backend,
                services,
                OpaqueIndexProjectionBuilder(
                    services[0].store.index,
                    SessionCandidateHandleProvider(
                        b"candidate-handle-test-key", b"query-nonce-00001"
                    ),
                ),
            )
            result = orchestrator.query(
                "request-1",
                "entity",
                ids.entity_id("Alice"),
                capacity=4,
            )

        self.assertEqual(result.candidate_values, {ids.entity_id("Alice"): 1})
        self.assertEqual(len(result.combined_slots.slot_handles), 4)
        self.assertFalse(hasattr(result.combined_slots, "matched_point"))


if __name__ == "__main__":
    unittest.main()

