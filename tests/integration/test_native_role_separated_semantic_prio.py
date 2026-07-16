import tempfile
import unittest
from pathlib import Path

from src.aggregation.prio3_backend import Prio3LocalBackend
from src.aggregation.prio3_candidates import (
    CandidateVectorConfig,
    PrioCandidateAggregator,
    SessionCandidateHandleProvider,
)
from src.crypto.fss_cli_backend import FssCliBackend
from src.crypto.hmac_ids import HmacIdProvider
from src.orchestration.prio_candidate_pipeline import LocalPrioCandidatePipeline
from src.orchestration.role_separated_encoded_matcher import RoleSeparatedEncodedGraphMatcher
from src.orchestration.role_separated_fss_query import RoleSeparatedFssQueryOrchestrator
from src.orchestration.role_separated_semantic_routing import RoleSeparatedSemanticRouter
from src.party.opaque_index_snapshot import OpaqueIndexSnapshot
from src.party.secure_index import SecurePartyIndex
from src.runtime.fss_evaluator_service import FssEvaluatorService, FssEvaluatorStore
from src.runtime.fss_projection_builder import OpaqueIndexProjectionBuilder
from src.runtime.opaque_index_replication import replicate_opaque_snapshots


class NativeRoleSeparatedSemanticPrioTest(unittest.TestCase):
    def test_native_semantic_two_hop_reaches_prio_topk(self):
        fss_executable = Path("build/fss_cli/fedkg-fss-cli")
        prio_executable = Path("tools/prio3_cli/target/release/fedkg-prio3-cli")
        if not fss_executable.exists() or not prio_executable.exists():
            self.skipTest("native FSS and Prio3 CLIs must be built")

        ids = HmacIdProvider(b"native-semantic-prio-key")
        parties = [
            SecurePartyIndex.from_plain_graph(
                "p0",
                {"Kismet": {"starred_actors": ["Marlene Dietrich"]}},
                {},
                ids,
            ),
            SecurePartyIndex.from_plain_graph(
                "p1",
                {"Marlene Dietrich": {"starred_actors": ["A Foreign Affair"]}},
                {},
                ids,
            ),
        ]
        fss = FssCliBackend.from_executable(fss_executable)
        handles = SessionCandidateHandleProvider(
            b"candidate-handle-test-key",
            b"query-nonce-00001",
        )
        with tempfile.TemporaryDirectory() as tmp:
            replicate_opaque_snapshots(
                [
                    OpaqueIndexSnapshot.from_secure_index(
                        party,
                        ids,
                        semantic_bucket_mode="alias",
                    )
                    for party in parties
                ],
                ["fss0", "fss1"],
                tmp,
            )
            stores = [FssEvaluatorStore.load(Path(tmp) / name) for name in ("fss0", "fss1")]
            lookup = RoleSeparatedFssQueryOrchestrator(
                fss,
                [FssEvaluatorService(store, fss) for store in stores],
                OpaqueIndexProjectionBuilder(stores[0].index, handles),
            )
            semantic = RoleSeparatedSemanticRouter(ids, lookup, bucket_mode="alias")
            matched = RoleSeparatedEncodedGraphMatcher(
                ids,
                lookup,
                stores[0].index,
                semantic_router=semantic,
                relation_capacity=4,
                entity_capacity=8,
            ).match(
                [
                    ("Kismet", "acted in", "UNKNOWN"),
                    ("UNKNOWN", "acted in", "A Foreign Affair"),
                ]
            )

        ranked = LocalPrioCandidatePipeline(
            PrioCandidateAggregator(
                Prio3LocalBackend.from_executable(prio_executable),
                CandidateVectorConfig(aggregator_count=3, capacity=4),
                handles,
            )
        ).run(matched.party_ids, matched.contributions, k=1)
        self.assertEqual(len(ranked.selected_candidate_ids), 1)
        self.assertEqual(ranked.selected_candidate_ids[0], matched.candidates[0].candidate_id)


if __name__ == "__main__":
    unittest.main()

