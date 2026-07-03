import unittest

from src.aggregation.private_lookup import PrivateLookupAggregator
from src.common.types import PrivateQueryShare
from src.crypto.dpf import DpfKeyShare
from src.crypto.hmac_ids import HmacIdProvider
from src.orchestration.private_universe import build_private_evaluation_universe
from src.party.private_evaluator import PrivatePartyEvaluator
from src.party.secure_index import SecurePartyIndex


class LocalAdditiveShareBackend:
    """Test-only additive DPF-like backend.

    p0 emits 1 at alpha and 0 elsewhere; p1 emits 0 everywhere. The aggregator
    still has to combine both parties before deciding a match.
    """

    def eval(self, key_share, point):
        if key_share.party_id == "p0" and key_share.payload["alpha"] == point:
            return 1
        return 0


class PrivatePartyEvaluatorTest(unittest.TestCase):
    def test_returns_raw_eval_shares_not_local_matches(self):
        ids = HmacIdProvider(b"test-key")
        index = SecurePartyIndex.from_plain_graph(
            "p0",
            {"Tom Hanks": {"acted in": ["Forrest Gump"]}, "Forrest Gump": {}},
            {"movie": ["Forrest Gump"]},
            ids,
        )
        share = PrivateQueryShare(
            party_id="p0",
            query_shape=[("Tom Hanks", "acted in", "UNKNOWN movie 1")],
            node_key_shares={"Tom Hanks": DpfKeyShare("p0", {"alpha": ids.entity_id("Tom Hanks")})},
            relation_key_shares={"acted in": DpfKeyShare("p0", {"alpha": ids.relation_id("acted in")})},
            type_key_shares={"UNKNOWN movie 1": DpfKeyShare("p0", {"alpha": ids.type_id("movie")})},
        )

        eval_shares = PrivatePartyEvaluator(index, LocalAdditiveShareBackend()).evaluate(share)

        self.assertIn(ids.entity_id("Tom Hanks"), eval_shares.node_eval_shares["Tom Hanks"])
        self.assertEqual(eval_shares.node_eval_shares["Tom Hanks"][ids.entity_id("Tom Hanks")], 1)
        self.assertIn(ids.relation_id("acted in"), eval_shares.relation_eval_shares["acted in"])
        self.assertEqual(
            eval_shares.type_eval_shares["UNKNOWN movie 1"][ids.type_id("movie")],
            1,
        )

    def test_aggregates_two_party_eval_shares_before_match_decision(self):
        ids = HmacIdProvider(b"test-key")
        p0 = SecurePartyIndex.from_plain_graph(
            "p0",
            {"Tom Hanks": {"acted in": ["Forrest Gump"]}, "Forrest Gump": {}},
            {"movie": ["Forrest Gump"]},
            ids,
        )
        p1 = SecurePartyIndex.from_plain_graph(
            "p1",
            {"Tom Hanks": {"acted in": ["Forrest Gump"]}, "Forrest Gump": {}},
            {"movie": ["Forrest Gump"]},
            ids,
        )
        query_shape = [("Tom Hanks", "acted in", "UNKNOWN movie 1")]
        shares = {
            party: PrivateQueryShare(
                party_id=party,
                query_shape=query_shape,
                node_key_shares={"Tom Hanks": DpfKeyShare(party, {"alpha": ids.entity_id("Tom Hanks")})},
                relation_key_shares={"acted in": DpfKeyShare(party, {"alpha": ids.relation_id("acted in")})},
                type_key_shares={"UNKNOWN movie 1": DpfKeyShare(party, {"alpha": ids.type_id("movie")})},
            )
            for party in ["p0", "p1"]
        }

        evaluated = [
            PrivatePartyEvaluator(p0, LocalAdditiveShareBackend()).evaluate(shares["p0"]),
            PrivatePartyEvaluator(p1, LocalAdditiveShareBackend()).evaluate(shares["p1"]),
        ]
        candidates = PrivateLookupAggregator(["p0", "p1"]).aggregate(evaluated)

        self.assertEqual(len(candidates.nodes["Tom Hanks"]), 2)
        self.assertEqual(len(candidates.relations["acted in"]), 2)
        self.assertEqual(len(candidates.nodes["UNKNOWN movie 1"]), 2)

    def test_shared_universe_handles_disjoint_party_local_points(self):
        ids = HmacIdProvider(b"test-key")
        p0 = SecurePartyIndex.from_plain_graph(
            "p0",
            {"Alice": {"knows": ["Movie A"]}, "Movie A": {}},
            {"movie": ["Movie A"]},
            ids,
        )
        p1 = SecurePartyIndex.from_plain_graph(
            "p1",
            {"Bob": {"knows": ["Movie B"]}, "Movie B": {}},
            {"movie": ["Movie B"]},
            ids,
        )
        query_shape = [("Alice", "knows", "UNKNOWN movie 1")]
        universe = build_private_evaluation_universe(query_shape, [p0, p1])
        shares = {
            party: PrivateQueryShare(
                party_id=party,
                query_shape=query_shape,
                node_key_shares={"Alice": DpfKeyShare(party, {"alpha": ids.entity_id("Alice")})},
                relation_key_shares={"knows": DpfKeyShare(party, {"alpha": ids.relation_id("knows")})},
                type_key_shares={"UNKNOWN movie 1": DpfKeyShare(party, {"alpha": ids.type_id("movie")})},
            )
            for party in ["p0", "p1"]
        }

        evaluated = [
            PrivatePartyEvaluator(p0, LocalAdditiveShareBackend()).evaluate(shares["p0"], universe),
            PrivatePartyEvaluator(p1, LocalAdditiveShareBackend()).evaluate(shares["p1"], universe),
        ]
        candidates = PrivateLookupAggregator(["p0", "p1"]).aggregate(evaluated)

        alice_candidates = candidates.nodes["Alice"]
        self.assertEqual({ref.party_id for ref in alice_candidates}, {"p0"})
        self.assertEqual({ref.party_id for ref in candidates.relations["knows"]}, {"p0", "p1"})
        self.assertEqual({ref.party_id for ref in candidates.nodes["UNKNOWN movie 1"]}, {"p0", "p1"})


if __name__ == "__main__":
    unittest.main()
