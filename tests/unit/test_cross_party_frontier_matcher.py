import unittest

from src.aggregation.score_aggregation import MatchScoreShareBuilder
from src.crypto.dpf import DpfKeyShare
from src.crypto.hmac_ids import HmacIdProvider
from src.orchestration.cross_party_frontier_matcher import CrossPartyFrontierMatcher
from src.party.secure_index import SecurePartyIndex
from src.ranking.garbled_circuit import LocalGarbledCircuitTopK


class LocalAnyPartyDpfBackend:
    def gen(self, alpha, beta, party_ids):
        return {party_id: DpfKeyShare(party_id, {"alpha": alpha}) for party_id in party_ids}

    def eval(self, key_share, point):
        return int(key_share.party_id == "p0" and key_share.payload["alpha"] == point)

    def eval_many(self, key_share, points):
        return [self.eval(key_share, point) for point in points]


class CrossPartyFrontierMatcherTest(unittest.TestCase):
    def test_two_hop_cross_party_frontier_handoff_returns_opaque_ranked_path(self):
        ids = HmacIdProvider(b"test-key")
        p0 = SecurePartyIndex.from_plain_graph(
            "p0",
            {"Tom Hanks": {"acted in": ["Forrest Gump"]}, "Forrest Gump": {}},
            {"movie": ["Forrest Gump"]},
            ids,
        )
        p1 = SecurePartyIndex.from_plain_graph(
            "p1",
            {"Forrest Gump": {"has genre": ["Drama"]}, "Drama": {}},
            {"genre": ["Drama"]},
            ids,
        )
        query = [
            ("Tom Hanks", "acted in", "UNKNOWN movie 1"),
            ("UNKNOWN movie 1", "has genre", "UNKNOWN genre 1"),
        ]
        matcher = CrossPartyFrontierMatcher(
            [p0, p1],
            ids,
            LocalAnyPartyDpfBackend(),
            MatchScoreShareBuilder(share_count=3),
        )

        path_shares = matcher.match_two_hop(query)
        self.assertEqual(len(path_shares), 1)
        self.assertFalse(hasattr(path_shares[0], "party_id"))
        self.assertEqual(len(path_shares[0].score_shares), 3)

        ranked = matcher.retrieve_ranked(query, LocalGarbledCircuitTopK(party_count=3), k=1)
        self.assertEqual(
            ranked.evidence[0].edges,
            [
                ("Tom Hanks", "acted in", "Forrest Gump"),
                ("Forrest Gump", "has genre", "Drama"),
            ],
        )

    def test_frontier_handoff_does_not_continue_without_matching_frontier(self):
        ids = HmacIdProvider(b"test-key")
        p0 = SecurePartyIndex.from_plain_graph(
            "p0",
            {"Tom Hanks": {"acted in": ["Forrest Gump"]}, "Forrest Gump": {}},
            {"movie": ["Forrest Gump"]},
            ids,
        )
        p1 = SecurePartyIndex.from_plain_graph(
            "p1",
            {"Apollo 13": {"has genre": ["Drama"]}, "Drama": {}},
            {"genre": ["Drama"]},
            ids,
        )
        query = [
            ("Tom Hanks", "acted in", "UNKNOWN movie 1"),
            ("UNKNOWN movie 1", "has genre", "UNKNOWN genre 1"),
        ]
        matcher = CrossPartyFrontierMatcher(
            [p0, p1],
            ids,
            LocalAnyPartyDpfBackend(),
            MatchScoreShareBuilder(share_count=3),
        )

        self.assertEqual(matcher.match_two_hop(query), [])

    def test_multi_hop_frontier_handoff_across_three_parties(self):
        ids = HmacIdProvider(b"test-key")
        p0 = SecurePartyIndex.from_plain_graph(
            "p0",
            {"Tom Hanks": {"acted in": ["Forrest Gump"]}, "Forrest Gump": {}},
            {"movie": ["Forrest Gump"]},
            ids,
        )
        p1 = SecurePartyIndex.from_plain_graph(
            "p1",
            {"Forrest Gump": {"has genre": ["Drama"]}, "Drama": {}},
            {"genre": ["Drama"]},
            ids,
        )
        p2 = SecurePartyIndex.from_plain_graph(
            "p2",
            {"Drama": {"associated award": ["Academy Award"]}, "Academy Award": {}},
            {"award": ["Academy Award"]},
            ids,
        )
        query = [
            ("Tom Hanks", "acted in", "UNKNOWN movie 1"),
            ("UNKNOWN movie 1", "has genre", "UNKNOWN genre 1"),
            ("UNKNOWN genre 1", "associated award", "UNKNOWN award 1"),
        ]
        matcher = CrossPartyFrontierMatcher(
            [p0, p1, p2],
            ids,
            LocalAnyPartyDpfBackend(),
            MatchScoreShareBuilder(share_count=3),
        )

        path_shares = matcher.match_multi_hop(query)
        self.assertEqual(len(path_shares), 1)
        self.assertFalse(hasattr(path_shares[0], "party_id"))

        ranked = matcher.retrieve_ranked(query, LocalGarbledCircuitTopK(party_count=3), k=1)
        self.assertEqual(
            ranked.evidence[0].edges,
            [
                ("Tom Hanks", "acted in", "Forrest Gump"),
                ("Forrest Gump", "has genre", "Drama"),
                ("Drama", "associated award", "Academy Award"),
            ],
        )

    def test_semantic_relation_routing_matches_alias_relation_labels(self):
        ids = HmacIdProvider(b"test-key")
        p0 = SecurePartyIndex.from_plain_graph(
            "p0",
            {"Kismet": {"starred_actors": ["Marlene Dietrich"]}, "Marlene Dietrich": {}},
            {},
            ids,
        )
        p1 = SecurePartyIndex.from_plain_graph(
            "p1",
            {"Marlene Dietrich": {"starred_actors": ["A Foreign Affair"]}, "A Foreign Affair": {}},
            {},
            ids,
        )
        query = [
            ("Kismet", "acted in", "UNKNOWN"),
            ("UNKNOWN", "acted in", "A Foreign Affair"),
        ]
        matcher = CrossPartyFrontierMatcher(
            [p0, p1],
            ids,
            LocalAnyPartyDpfBackend(),
            MatchScoreShareBuilder(share_count=3),
            enable_semantic_relations=True,
            semantic_relation_penalty=0.25,
        )

        ranked = matcher.retrieve_ranked(query, LocalGarbledCircuitTopK(party_count=3), k=1)

        self.assertEqual(
            ranked.evidence[0].edges,
            [
                ("Kismet", "starred_actors", "Marlene Dietrich"),
                ("Marlene Dietrich", "starred_actors", "A Foreign Affair"),
            ],
        )
        self.assertEqual(ranked.evidence[0].score, 0.5)


if __name__ == "__main__":
    unittest.main()
