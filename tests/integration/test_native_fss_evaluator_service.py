import json
import tempfile
import unittest
from pathlib import Path

from src.crypto.fss_cli_backend import FssCliBackend
from src.crypto.hmac_ids import HmacIdProvider
from src.party.opaque_index_snapshot import OpaqueIndexSnapshot
from src.party.secure_index import SecurePartyIndex
from src.runtime.fss_evaluator_service import (
    FssEvaluatorRequest,
    FssEvaluatorService,
    FssEvaluatorStore,
)
from src.runtime.fss_candidate_projection import CandidateProjection, ProjectedFssCoordinator
from src.runtime.opaque_index_replication import replicate_opaque_snapshots


class NativeFssEvaluatorServiceTest(unittest.TestCase):
    def test_two_evaluator_services_return_reconstructable_shares(self):
        executable = Path("build/fss_cli/fedkg-fss-cli")
        if not executable.exists():
            self.skipTest("native FSS CLI is not built")

        ids = HmacIdProvider(b"native-evaluator-test-key")
        party = SecurePartyIndex.from_plain_graph(
            "p0",
            {"Alice": {"knows": ["Bob"]}, "Bob": {}},
            {},
            ids,
        )
        snapshot = OpaqueIndexSnapshot.from_secure_index(party, ids)
        backend = FssCliBackend.from_executable(executable)
        key_shares = backend.gen(ids.entity_id("Alice"), 1, ["fss0", "fss1"])

        with tempfile.TemporaryDirectory() as tmp:
            replicate_opaque_snapshots([snapshot], ["fss0", "fss1"], tmp)
            responses = []
            stores = []
            for evaluator_id in ("fss0", "fss1"):
                store = FssEvaluatorStore.load(Path(tmp) / evaluator_id)
                stores.append(store)
                responses.append(
                    FssEvaluatorService(store, backend).evaluate(
                        FssEvaluatorRequest(
                            "native-request",
                            "entity",
                            key_shares[evaluator_id],
                        )
                    )
                )

        self.assertEqual(responses[0].universe_digest, responses[1].universe_digest)
        self.assertEqual(responses[0].point_count, responses[1].point_count)
        points = stores[0].points_for("entity")
        reconstructed = [
            (left + right) % (1 << 64)
            for left, right in zip(responses[0].value_shares, responses[1].value_shares)
        ]
        matched = [point for point, value in zip(points, reconstructed) if value != 0]
        self.assertEqual(matched, [ids.entity_id("Alice")])
        self.assertFalse(hasattr(responses[0], "matched_point"))
        self.assertFalse(hasattr(responses[1], "matched_point"))

    def test_native_services_project_directly_into_candidate_slots(self):
        executable = Path("build/fss_cli/fedkg-fss-cli")
        if not executable.exists():
            self.skipTest("native FSS CLI is not built")

        ids = HmacIdProvider(b"native-projection-test-key")
        alice_id = ids.entity_id("Alice")
        bob_id = ids.entity_id("Bob")
        party = SecurePartyIndex.from_plain_graph(
            "p0", {"Alice": {"knows": ["Bob"]}, "Bob": {}}, {}, ids
        )
        backend = FssCliBackend.from_executable(executable)
        key_shares = backend.gen(alice_id, 1, ["fss0", "fss1"])
        projection = CandidateProjection(
            slot_handles=("candidate-a", "candidate-b", "padding"),
            point_weights={
                alice_id: {"candidate-a": 1},
                bob_id: {"candidate-b": 1},
            },
        )

        with tempfile.TemporaryDirectory() as tmp:
            replicate_opaque_snapshots(
                [OpaqueIndexSnapshot.from_secure_index(party, ids)], ["fss0", "fss1"], tmp
            )
            responses = [
                FssEvaluatorService(
                    FssEvaluatorStore.load(Path(tmp) / evaluator_id), backend
                ).evaluate_projected(
                    FssEvaluatorRequest("projected-request", "entity", key_shares[evaluator_id]),
                    projection,
                )
                for evaluator_id in ("fss0", "fss1")
            ]

        combined = ProjectedFssCoordinator().combine(responses)
        self.assertEqual(combined.values, [1, 0, 0])
        self.assertEqual(combined.nonzero_slots, {"candidate-a": 1})
        for response in responses:
            serialized = response.as_dict()
            self.assertNotIn("value_shares", serialized)
            self.assertNotIn("matched_point", serialized)
            self.assertNotIn(alice_id, json.dumps(serialized))


if __name__ == "__main__":
    unittest.main()
