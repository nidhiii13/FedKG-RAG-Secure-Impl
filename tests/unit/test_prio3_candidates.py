import unittest

from src.aggregation.prio3_candidates import (
    CandidateContribution,
    CandidateVectorConfig,
    PrioCandidateAggregator,
    SessionCandidateHandleProvider,
)
from src.aggregation.prio3_types import Prio3SumVecResult


class SummingBackend:
    def __init__(self):
        self.requests = []

    def sum_vec(self, request):
        request.validate()
        self.requests.append(request)
        return Prio3SumVecResult(
            aggregate=[sum(column) for column in zip(*request.measurements)],
            aggregator_count=request.aggregator_count,
            report_count=len(request.measurements),
        )


class PrioCandidateAggregatorTest(unittest.TestCase):
    def setUp(self):
        self.backend = SummingBackend()
        self.aggregator = PrioCandidateAggregator(
            self.backend,
            CandidateVectorConfig(aggregator_count=3, capacity=4),
            SessionCandidateHandleProvider(b"candidate-handle-test-key", b"query-nonce-00001"),
        )

    def test_aggregates_presence_score_and_support_across_three_parties(self):
        result = self.aggregator.aggregate(
            ["p0", "p1", "p2"],
            [
                CandidateContribution("p0", "candidate-a", 0.2, 2),
                CandidateContribution("p0", "candidate-b", 0.5, 1),
                CandidateContribution("p1", "candidate-a", 0.4, 2),
                CandidateContribution("p2", "candidate-c", 0.1, 3),
            ],
        )

        by_id = {candidate.candidate_id: candidate for candidate in result.candidates}
        self.assertEqual(by_id["candidate-a"].presence_count, 2)
        self.assertEqual(by_id["candidate-a"].score_sum, 600_000)
        self.assertEqual(by_id["candidate-a"].support_sum, 4)
        self.assertAlmostEqual(by_id["candidate-a"].average_score, 0.3)
        self.assertEqual(len(result.slots), 4)
        self.assertEqual(sum(slot.is_padding for slot in result.slots), 1)
        self.assertEqual([request.bits for request in self.backend.requests], [1, 32, 16])

    def test_handles_are_query_scoped(self):
        first = SessionCandidateHandleProvider(
            b"candidate-handle-test-key", b"query-nonce-00001"
        ).candidate_handle("candidate-a")
        second = SessionCandidateHandleProvider(
            b"candidate-handle-test-key", b"query-nonce-00002"
        ).candidate_handle("candidate-a")
        self.assertNotEqual(first, second)

    def test_rejects_duplicate_party_candidate_contribution(self):
        with self.assertRaises(ValueError):
            self.aggregator.aggregate(
                ["p0", "p1"],
                [
                    CandidateContribution("p0", "candidate-a", 0.2, 1),
                    CandidateContribution("p0", "candidate-a", 0.3, 1),
                ],
            )


if __name__ == "__main__":
    unittest.main()

