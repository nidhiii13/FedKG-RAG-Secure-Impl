import tempfile
import unittest

from src.crypto.dpf import DpfKeyShare
from src.crypto.hmac_ids import HmacIdProvider
from src.party.opaque_index_snapshot import OpaqueIndexSnapshot
from src.party.secure_index import SecurePartyIndex
from src.runtime.fss_evaluator_service import (
    FssEvaluatorRequest,
    FssEvaluatorService,
    FssEvaluatorStore,
)
from src.runtime.opaque_index_replication import replicate_opaque_snapshots


class PointBackend:
    def eval(self, key_share, point):
        return int(key_share.payload["alpha"] == point)

    def eval_many(self, key_share, points):
        return [self.eval(key_share, point) for point in points]


class FssEvaluatorServiceTest(unittest.TestCase):
    def setUp(self):
        self.ids = HmacIdProvider(b"fss-evaluator-test-key")
        index = SecurePartyIndex.from_plain_graph(
            "p0",
            {"Alice": {"knows": ["Bob"]}, "Bob": {}},
            {"person": ["Alice", "Bob"]},
            self.ids,
        )
        self.snapshot = OpaqueIndexSnapshot.from_secure_index(index, self.ids)

    def test_evaluator_returns_aligned_shares_without_match_decision(self):
        with tempfile.TemporaryDirectory() as tmp:
            replicate_opaque_snapshots([self.snapshot], ["fss0", "fss1"], tmp)
            store = FssEvaluatorStore.load(f"{tmp}/fss0", expected_evaluator_id="fss0")
            service = FssEvaluatorService(store, PointBackend())
            response = service.evaluate(
                FssEvaluatorRequest(
                    "request-1",
                    "entity",
                    DpfKeyShare("fss0", {"party": 0, "alpha": self.ids.entity_id("Alice")}),
                )
            )

        self.assertEqual(response.point_count, 2)
        self.assertEqual(len(response.value_shares), 2)
        self.assertFalse(hasattr(response, "matched_point"))
        self.assertEqual(sum(response.value_shares), 1)

    def test_evaluator_rejects_other_evaluator_share(self):
        with tempfile.TemporaryDirectory() as tmp:
            replicate_opaque_snapshots([self.snapshot], ["fss0", "fss1"], tmp)
            service = FssEvaluatorService(FssEvaluatorStore.load(f"{tmp}/fss0"), PointBackend())
            with self.assertRaisesRegex(ValueError, "different evaluator"):
                service.evaluate(
                    FssEvaluatorRequest(
                        "request-1",
                        "entity",
                        DpfKeyShare("fss1", {"party": 1, "alpha": self.ids.entity_id("Alice")}),
                    )
                )

    def test_evaluator_rejects_wrong_native_share_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            replicate_opaque_snapshots([self.snapshot], ["fss0", "fss1"], tmp)
            service = FssEvaluatorService(FssEvaluatorStore.load(f"{tmp}/fss0"), PointBackend())
            with self.assertRaisesRegex(ValueError, "share index"):
                service.evaluate(
                    FssEvaluatorRequest(
                        "request-1",
                        "entity",
                        DpfKeyShare("fss0", {"party": 1, "alpha": self.ids.entity_id("Alice")}),
                    )
                )


if __name__ == "__main__":
    unittest.main()

