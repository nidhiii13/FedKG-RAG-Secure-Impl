import unittest

from src.aggregation.score_aggregation import MatchScoreShareBuilder
from src.crypto.hmac_ids import HmacIdProvider
from src.gateway.query_compiler import ExactQueryCompiler
from src.orchestration.opaque_path_pipeline import OpaquePathAggregator
from src.party.private_structural_matcher import PartyLocalStructuralMatcher
from src.party.secure_index import SecurePartyIndex
from src.ranking.garbled_circuit import LocalGarbledCircuitTopK


class PartyLocalStructuralMatcherTest(unittest.TestCase):
    def test_party_local_matcher_returns_opaque_shares_and_reveals_only_selected(self):
        ids = HmacIdProvider(b"test-key")
        p0 = SecurePartyIndex.from_plain_graph(
            "p0",
            {"Kismet": {"starred_actors": ["Marlene Dietrich"]}, "Marlene Dietrich": {}},
            {},
            ids,
        )
        p1 = SecurePartyIndex.from_plain_graph(
            "p1",
            {"Blue Angel": {"starred_actors": ["Marlene Dietrich"]}, "Marlene Dietrich": {}},
            {},
            ids,
        )
        query = [("Kismet", "starred_actors", "Marlene Dietrich")]
        exact = ExactQueryCompiler(ids).compile_ids(query)
        builder = MatchScoreShareBuilder(share_count=3)
        m0 = PartyLocalStructuralMatcher(p0, builder)
        m1 = PartyLocalStructuralMatcher(p1, builder)

        batch0 = m0.match_exact(query, exact)
        batch1 = m1.match_exact(query, exact)

        self.assertEqual(len(batch0.path_shares), 1)
        self.assertEqual(len(batch1.path_shares), 0)
        share = batch0.path_shares[0]
        self.assertEqual(len(share.score_shares), 3)
        self.assertEqual(len(share.support_shares), 3)
        self.assertFalse(hasattr(share, "party_id"))

        result = OpaquePathAggregator(LocalGarbledCircuitTopK(party_count=3)).run(
            [batch0.path_shares, batch1.path_shares],
            [m0, m1],
            k=1,
        )

        self.assertEqual(result.evidence[0].edges, [("Kismet", "starred_actors", "Marlene Dietrich")])
        self.assertEqual(len(result.selected_ids), 1)

    def test_party_local_matcher_does_not_return_false_edge_from_separate_candidates(self):
        ids = HmacIdProvider(b"test-key")
        party = SecurePartyIndex.from_plain_graph(
            "p0",
            {
                "Kismet": {"directed_by": ["Vincente Minnelli"]},
                "Blue Angel": {"starred_actors": ["Marlene Dietrich"]},
                "Vincente Minnelli": {},
                "Marlene Dietrich": {},
            },
            {},
            ids,
        )
        query = [("Kismet", "starred_actors", "Marlene Dietrich")]
        exact = ExactQueryCompiler(ids).compile_ids(query)
        matcher = PartyLocalStructuralMatcher(party, MatchScoreShareBuilder(share_count=3))

        result = matcher.match_exact(query, exact)

        self.assertEqual(result.path_shares, [])


if __name__ == "__main__":
    unittest.main()
