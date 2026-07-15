import unittest

from src.runtime.fss_candidate_projection import (
    CandidateProjection,
    ProjectedFssCoordinator,
    ProjectedFssEvaluatorResponse,
)


class FssCandidateProjectionTest(unittest.TestCase):
    def test_projects_eval_shares_without_returning_matched_point(self):
        projection = CandidateProjection(
            slot_handles=("slot-a", "slot-b", "padding"),
            point_weights={
                "point-a": {"slot-a": 1},
                "point-b": {"slot-b": 1},
            },
        )
        projected = projection.project(["point-a", "point-b"], [17, 23])
        self.assertEqual(projected, [17, 23, 0])

    def test_coordinator_combines_only_candidate_slots(self):
        modulus = 1 << 64
        common = {
            "request_id": "request-1",
            "domain": "relation",
            "universe_digest": "universe-digest",
            "projection_digest": "projection-digest",
            "slot_handles": ("slot-a", "slot-b", "padding"),
        }
        responses = [
            ProjectedFssEvaluatorResponse(
                evaluator_id="fss0",
                evaluator_index=0,
                candidate_slot_shares=[100, 50, 9],
                **common,
            ),
            ProjectedFssEvaluatorResponse(
                evaluator_id="fss1",
                evaluator_index=1,
                candidate_slot_shares=[modulus - 99, modulus - 50, modulus - 9],
                **common,
            ),
        ]
        combined = ProjectedFssCoordinator().combine(responses)
        self.assertEqual(combined.values, [1, 0, 0])
        self.assertEqual(combined.nonzero_slots, {"slot-a": 1})
        self.assertFalse(hasattr(combined, "matched_point"))

    def test_coordinator_rejects_projection_digest_mismatch(self):
        base = dict(
            request_id="request-1",
            domain="entity",
            universe_digest="same",
            slot_handles=("slot-a",),
            candidate_slot_shares=[0],
        )
        with self.assertRaisesRegex(ValueError, "projection_digest"):
            ProjectedFssCoordinator().combine(
                [
                    ProjectedFssEvaluatorResponse(
                        evaluator_id="fss0", evaluator_index=0, projection_digest="a", **base
                    ),
                    ProjectedFssEvaluatorResponse(
                        evaluator_id="fss1", evaluator_index=1, projection_digest="b", **base
                    ),
                ]
            )


if __name__ == "__main__":
    unittest.main()

