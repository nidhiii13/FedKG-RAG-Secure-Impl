import unittest

from src.aggregation.score_aggregation import CandidateShare, ShareAggregator
from src.aggregation.secret_sharing import AdditiveSharing, FixedPointEncoder


class SecretSharingTest(unittest.TestCase):
    def test_fixed_point_roundtrip_and_sharing(self):
        encoder = FixedPointEncoder()
        sharing = AdditiveSharing()
        value = encoder.encode(0.91)
        shares = sharing.share(value, 3)
        self.assertEqual(sharing.combine(shares), value)
        self.assertAlmostEqual(encoder.decode(value), 0.91, places=6)

    def test_aggregates_by_candidate_id(self):
        sharing = AdditiveSharing(field=101)
        aggregator = ShareAggregator(sharing)
        result = aggregator.aggregate(
            [
                CandidateShare("a", [1, 2, 3], [1, 0, 0]),
                CandidateShare("a", [4, 5, 6], [0, 1, 0]),
                CandidateShare("b", [7, 8, 9], [0, 0, 1]),
            ]
        )
        self.assertEqual(result["a"].score_shares, [5, 7, 9])
        self.assertEqual(result["a"].support_shares, [1, 1, 0])
        self.assertEqual(result["b"].score_shares, [7, 8, 9])


if __name__ == "__main__":
    unittest.main()
