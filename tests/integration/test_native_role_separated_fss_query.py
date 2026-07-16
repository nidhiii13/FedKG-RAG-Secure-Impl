import tempfile
import unittest
from pathlib import Path

from src.aggregation.prio3_candidates import SessionCandidateHandleProvider
from src.crypto.fss_cli_backend import FssCliBackend
from src.crypto.hmac_ids import HmacIdProvider
from src.orchestration.role_separated_fss_query import RoleSeparatedFssQueryOrchestrator
from src.party.opaque_index_snapshot import OpaqueIndexSnapshot
from src.party.secure_index import SecurePartyIndex
from src.runtime.fss_evaluator_service import FssEvaluatorService, FssEvaluatorStore
from src.runtime.fss_projection_builder import OpaqueIndexProjectionBuilder
from src.runtime.opaque_index_replication import replicate_opaque_snapshots


class NativeRoleSeparatedFssQueryTest(unittest.TestCase):
    def test_native_exact_query_reaches_candidate_slot_through_two_services(self):
        executable = Path("build/fss_cli/fedkg-fss-cli")
        if not executable.exists():
            self.skipTest("native FSS CLI is not built")
        ids = HmacIdProvider(b"native-role-separated-query-key")
        party = SecurePartyIndex.from_plain_graph(
            "p0", {"Alice": {"knows": ["Bob"]}, "Bob": {}}, {}, ids
        )
        backend = FssCliBackend.from_executable(executable)
        with tempfile.TemporaryDirectory() as tmp:
            replicate_opaque_snapshots(
                [OpaqueIndexSnapshot.from_secure_index(party, ids)], ["fss0", "fss1"], tmp
            )
            stores = [FssEvaluatorStore.load(Path(tmp) / name) for name in ("fss0", "fss1")]
            result = RoleSeparatedFssQueryOrchestrator(
                backend,
                [FssEvaluatorService(store, backend) for store in stores],
                OpaqueIndexProjectionBuilder(
                    stores[0].index,
                    SessionCandidateHandleProvider(
                        b"candidate-handle-test-key", b"query-nonce-00001"
                    ),
                ),
            ).query("native-query", "entity", ids.entity_id("Alice"), capacity=4)

        self.assertEqual(result.candidate_values, {ids.entity_id("Alice"): 1})
        self.assertEqual(len(result.combined_slots.slot_handles), 4)


if __name__ == "__main__":
    unittest.main()

