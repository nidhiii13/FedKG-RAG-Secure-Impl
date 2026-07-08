import unittest

from src.crypto.hmac_ids import HmacIdProvider
from src.party.secure_index import SecurePartyIndex
from src.semantic.relation_buckets import (
    RelationSemanticIndex,
    relation_alias_bucket_names,
    relation_bucket_names,
    relation_bucket_tokens,
    relation_lsh_bucket_names,
)


class SemanticRelationBucketsTest(unittest.TestCase):
    def test_relation_alias_buckets_connect_acted_and_starred_actors(self):
        self.assertIn("alias:actor", relation_alias_bucket_names("acted in"))
        self.assertIn("alias:actor", relation_alias_bucket_names("starred_actors"))

    def test_relation_lsh_buckets_are_deterministic_and_band_prefixed(self):
        first = relation_lsh_bucket_names("directed by")
        second = relation_lsh_bucket_names("directed by")

        self.assertEqual(first, second)
        self.assertTrue(first)
        self.assertTrue(all(bucket.startswith("lsh:") for bucket in first))

    def test_hybrid_buckets_include_alias_and_lsh(self):
        buckets = relation_bucket_names("acted in", mode="hybrid")

        self.assertIn("alias:actor", buckets)
        self.assertTrue(any(bucket.startswith("lsh:") for bucket in buckets))

    def test_party_semantic_index_maps_bucket_tokens_to_relation_ids(self):
        ids = HmacIdProvider(b"test-key")
        index = SecurePartyIndex.from_plain_graph(
            "p0",
            {"Kismet": {"starred_actors": ["Marlene Dietrich"]}},
            {},
            ids,
        )
        semantic = RelationSemanticIndex.from_secure_index(index, ids)
        actor_bucket = relation_bucket_tokens(ids, "acted in")[0]
        matching_tokens = set(relation_bucket_tokens(ids, "acted in", mode="hybrid")) & set(semantic.tokens)

        self.assertNotIn(actor_bucket, set())
        self.assertTrue(matching_tokens)
        relation_ids = {relation for token in matching_tokens for relation in semantic.relations_for(token)}
        self.assertIn(ids.relation_id("starred_actors"), relation_ids)


if __name__ == "__main__":
    unittest.main()
