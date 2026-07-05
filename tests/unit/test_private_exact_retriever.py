import unittest

from src.common.types import PrivateQueryShare
from src.crypto.dpf import DpfKeyShare
from src.crypto.hmac_ids import HmacIdProvider
from src.orchestration.private_exact_retriever import PrivateExactRetriever
from src.party.secure_index import SecurePartyIndex
from src.ranking.garbled_circuit import LocalGarbledCircuitTopK
from src.ranking.secure_topk import PrototypeRevealingTopK


class LocalAnyPartyDpfBackend:
    def gen(self, alpha, beta, party_ids):
        return {party_id: DpfKeyShare(party_id, {"alpha": alpha}) for party_id in party_ids}

    def eval(self, key_share, point):
        return int(key_share.party_id == "p0" and key_share.payload["alpha"] == point)


class PrivateExactRetrieverTest(unittest.TestCase):
    def test_private_exact_retrieval_preserves_structural_path(self):
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

        result = PrivateExactRetriever([p0, p1], ids, LocalAnyPartyDpfBackend(), final_topk=1).retrieve(query)

        self.assertEqual(
            result["results"][0].edges,
            [
                ("Tom Hanks", "acted in", "Forrest Gump"),
                ("Forrest Gump", "has genre", "Drama"),
            ],
        )

    def test_private_exact_retrieval_runs_ranking_and_controlled_reveal(self):
        ids = HmacIdProvider(b"test-key")
        p0 = SecurePartyIndex.from_plain_graph(
            "p0",
            {"Tom Hanks": {"acted in": ["Forrest Gump"]}, "Forrest Gump": {}},
            {"movie": ["Forrest Gump"]},
            ids,
        )
        query = [("Tom Hanks", "acted in", "UNKNOWN movie 1")]

        result = PrivateExactRetriever([p0], ids, LocalAnyPartyDpfBackend(), final_topk=1).retrieve_ranked(
            query,
            PrototypeRevealingTopK(),
        )

        self.assertEqual(
            result["ranked_results"][0].edges,
            [("Tom Hanks", "acted in", "Forrest Gump")],
        )
        self.assertEqual(len(result["selected_candidate_ids"]), 1)
        self.assertEqual(len(result["aggregated_score_shares"]), 1)

    def test_private_exact_retrieval_preserves_three_party_structural_path(self):
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

        result = PrivateExactRetriever([p0, p1, p2], ids, LocalAnyPartyDpfBackend(), final_topk=1).retrieve_ranked(
            query,
            LocalGarbledCircuitTopK(party_count=3),
        )

        self.assertEqual(
            result["ranked_results"][0].edges,
            [
                ("Tom Hanks", "acted in", "Forrest Gump"),
                ("Forrest Gump", "has genre", "Drama"),
                ("Drama", "associated award", "Academy Award"),
            ],
        )
        candidate = next(iter(result["aggregated_score_shares"].values()))
        self.assertEqual(len(candidate.score_shares), 3)
        self.assertEqual(len(candidate.support_shares), 3)


if __name__ == "__main__":
    unittest.main()
