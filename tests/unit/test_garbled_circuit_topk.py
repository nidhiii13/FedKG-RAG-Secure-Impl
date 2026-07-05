import unittest

from src.aggregation.score_aggregation import CandidateShare
from src.aggregation.secret_sharing import AdditiveSharing, FixedPointEncoder
from src.ranking.garbled_circuit import LocalGarbledCircuitTopK, garbled_rank_key_better


class GarbledCircuitTopKTest(unittest.TestCase):
    def test_garbled_comparator_prefers_lower_score(self):
        self.assertTrue(garbled_rank_key_better(10, 1, 20, 1, 8))
        self.assertFalse(garbled_rank_key_better(20, 1, 10, 1, 8))

    def test_garbled_comparator_uses_higher_support_tie_break(self):
        self.assertTrue(garbled_rank_key_better(10, 3, 10, 1, 8))
        self.assertFalse(garbled_rank_key_better(10, 1, 10, 3, 8))

    def test_local_garbled_topk_handles_three_party_shares(self):
        sharing = AdditiveSharing(field=65537)
        encoder = FixedPointEncoder(scale=100, field=65537)
        better = CandidateShare(
            "better",
            sharing.share(encoder.encode(0.12), 3),
            sharing.share(2, 3),
        )
        worse = CandidateShare(
            "worse",
            sharing.share(encoder.encode(0.91), 3),
            sharing.share(4, 3),
        )
        selected = LocalGarbledCircuitTopK(sharing=sharing, min_bit_width=16, party_count=3).rank([worse, better], 1)
        self.assertEqual(selected, ["better"])

    def test_local_garbled_topk_handles_n_party_shares(self):
        sharing = AdditiveSharing(field=65537)
        encoder = FixedPointEncoder(scale=100, field=65537)
        candidates = [
            CandidateShare("third", sharing.share(encoder.encode(0.40), 5), sharing.share(1, 5)),
            CandidateShare("first", sharing.share(encoder.encode(0.10), 5), sharing.share(1, 5)),
            CandidateShare("second", sharing.share(encoder.encode(0.20), 5), sharing.share(3, 5)),
        ]
        selected = LocalGarbledCircuitTopK(sharing=sharing, min_bit_width=16, party_count=5).rank(candidates, 2)
        self.assertEqual(selected, ["first", "second"])

    def test_local_garbled_topk_rejects_wrong_share_count(self):
        sharing = AdditiveSharing(field=65537)
        bad = CandidateShare("bad", sharing.share(10, 2), sharing.share(1, 2))
        with self.assertRaisesRegex(ValueError, "expected 3"):
            LocalGarbledCircuitTopK(sharing=sharing, min_bit_width=16, party_count=3).rank([bad], 1)


if __name__ == "__main__":
    unittest.main()
