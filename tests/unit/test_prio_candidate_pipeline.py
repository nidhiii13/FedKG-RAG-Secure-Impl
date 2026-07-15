import unittest

from src.aggregation.prio3_candidates import (
    CandidateContribution,
    CandidateVectorConfig,
    PrioCandidateAggregator,
    SessionCandidateHandleProvider,
)
from src.aggregation.prio3_types import Prio3SumVecResult
from src.orchestration.prio_candidate_pipeline import LocalPrioCandidatePipeline


class SummingBackend:
    def sum_vec(self, request):
        request.validate()
        return Prio3SumVecResult(
            [sum(column) for column in zip(*request.measurements)],
            request.aggregator_count,
            len(request.measurements),
        )


class LocalPrioCandidatePipelineTest(unittest.TestCase):
    def setUp(self):
        aggregator = PrioCandidateAggregator(
            SummingBackend(),
            CandidateVectorConfig(aggregator_count=3, capacity=8),
            SessionCandidateHandleProvider(b"candidate-handle-test-key", b"query-nonce-00001"),
        )
        self.pipeline = LocalPrioCandidatePipeline(aggregator)

    def test_ranks_average_score_then_support(self):
        result = self.pipeline.run(
            ["p0", "p1", "p2"],
            [
                CandidateContribution("p0", "a", 0.4, 1),
                CandidateContribution("p1", "a", 0.2, 1),
                CandidateContribution("p0", "b", 0.3, 3),
                CandidateContribution("p2", "c", 0.8, 5),
            ],
            k=2,
        )
        self.assertEqual(result.selected_candidate_ids, ["b", "a"])
        self.assertEqual(result.security.lookup_evaluator_count, 2)
        self.assertEqual(result.aggregation.aggregator_count, 3)

    def test_rejects_claim_of_multi_party_native_fss(self):
        with self.assertRaisesRegex(ValueError, "exactly two lookup evaluators"):
            self.pipeline.run(["p0", "p1", "p2"], [], k=1, lookup_evaluator_count=3)


if __name__ == "__main__":
    unittest.main()

