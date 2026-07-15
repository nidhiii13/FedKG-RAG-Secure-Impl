import unittest
from pathlib import Path

from src.aggregation.prio3_backend import Prio3LocalBackend
from src.aggregation.prio3_candidates import (
    CandidateContribution,
    CandidateVectorConfig,
    PrioCandidateAggregator,
    SessionCandidateHandleProvider,
)


class NativePrio3CandidateAggregationTest(unittest.TestCase):
    def test_three_party_candidate_vectors_use_three_prio_aggregators(self):
        executable = Path("tools/prio3_cli/target/release/fedkg-prio3-cli")
        if not executable.exists():
            self.skipTest("native Prio3 CLI is not built")

        aggregator = PrioCandidateAggregator(
            Prio3LocalBackend.from_executable(executable),
            CandidateVectorConfig(aggregator_count=3, capacity=8),
            SessionCandidateHandleProvider(b"candidate-handle-test-key", b"query-nonce-00001"),
        )
        result = aggregator.aggregate(
            ["party_0", "party_1", "party_2"],
            [
                CandidateContribution("party_0", "path-a", 0.25, 2),
                CandidateContribution("party_1", "path-a", 0.50, 2),
                CandidateContribution("party_1", "path-b", 0.10, 1),
                CandidateContribution("party_2", "path-c", 0.75, 3),
            ],
        )

        by_id = {candidate.candidate_id: candidate for candidate in result.candidates}
        self.assertEqual(result.aggregator_count, 3)
        self.assertEqual(result.party_count, 3)
        self.assertEqual(by_id["path-a"].presence_count, 2)
        self.assertEqual(by_id["path-a"].score_sum, 750_000)
        self.assertEqual(by_id["path-a"].support_sum, 4)
        self.assertAlmostEqual(by_id["path-a"].average_score, 0.375)


if __name__ == "__main__":
    unittest.main()

