import unittest

from src.common.types import PrivateQueryShare
from src.crypto.dpf import DpfKeyShare
from src.crypto.hmac_ids import HmacIdProvider
from src.orchestration.private_exact_retriever import PrivateExactRetriever
from src.party.secure_index import SecurePartyIndex


class LocalTwoPartyDpfBackend:
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

        result = PrivateExactRetriever([p0, p1], ids, LocalTwoPartyDpfBackend(), final_topk=1).retrieve(query)

        self.assertEqual(
            result["results"][0].edges,
            [
                ("Tom Hanks", "acted in", "Forrest Gump"),
                ("Forrest Gump", "has genre", "Drama"),
            ],
        )


if __name__ == "__main__":
    unittest.main()
