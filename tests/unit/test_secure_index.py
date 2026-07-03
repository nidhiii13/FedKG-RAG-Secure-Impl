import unittest

from src.crypto.dpf_domain import DpfProjectionCollisionError
from src.crypto.hmac_ids import HmacIdProvider
from src.gateway.query_compiler import ExactQueryCompiler
from src.orchestration.encoded_exact_retriever import EncodedExactRetriever
from src.party.secure_index import SecurePartyIndex


class SecureIndexTest(unittest.TestCase):
    def test_encoded_retriever_preserves_cross_party_structure(self):
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
        exact = ExactQueryCompiler(ids).compile_ids(query)
        result = EncodedExactRetriever([p0, p1], final_topk=1).retrieve(query, exact)
        self.assertEqual(
            result["results"][0].edges,
            [
                ("Tom Hanks", "acted in", "Forrest Gump"),
                ("Forrest Gump", "has genre", "Drama"),
            ],
        )

    def test_rejects_dpf_projection_collision_in_party_index(self):
        class CollidingIds:
            def __init__(self):
                self.real = HmacIdProvider(b"test-key")

            def entity_id(self, value):
                if value == "Alice":
                    return "a" * 16 + "00"
                if value == "Bob":
                    return "a" * 16 + "11"
                return self.real.entity_id(value)

            def relation_id(self, value):
                return self.real.relation_id(value)

            def type_id(self, value):
                return self.real.type_id(value)

        with self.assertRaises(DpfProjectionCollisionError):
            SecurePartyIndex.from_plain_graph(
                "p0",
                {"Alice": {"knows": ["Bob"]}, "Bob": {}},
                None,
                CollidingIds(),
            )


if __name__ == "__main__":
    unittest.main()
