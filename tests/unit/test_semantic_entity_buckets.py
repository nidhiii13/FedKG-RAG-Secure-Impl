import unittest

from src.crypto.hmac_ids import HmacIdProvider
from src.party.secure_index import SecurePartyIndex
from src.semantic.entity_buckets import (
    EntitySemanticIndex,
    entity_alias_bucket_names,
    entity_bucket_names,
    entity_bucket_tokens,
    entity_lsh_bucket_names,
)


class SemanticEntityBucketsTest(unittest.TestCase):
    def test_entity_alias_buckets_ignore_leading_article(self):
        self.assertIn("entity_tok:foreign", entity_alias_bucket_names("Foreign Affair"))
        self.assertIn("entity_tok:foreign", entity_alias_bucket_names("A Foreign Affair"))
        self.assertIn("entity_bigram:foreign:affair", entity_alias_bucket_names("A Foreign Affair"))

    def test_entity_lsh_buckets_are_deterministic_and_namespaced(self):
        first = entity_lsh_bucket_names("A Foreign Affair")
        second = entity_lsh_bucket_names("A Foreign Affair")

        self.assertEqual(first, second)
        self.assertTrue(first)
        self.assertTrue(all(bucket.startswith("entity_lsh:") for bucket in first))

    def test_hybrid_entity_buckets_include_alias_and_lsh(self):
        buckets = entity_bucket_names("A Foreign Affair", mode="hybrid")

        self.assertIn("entity_tok:foreign", buckets)
        self.assertTrue(any(bucket.startswith("entity_lsh:") for bucket in buckets))

    def test_party_semantic_entity_index_maps_bucket_tokens_to_entity_ids(self):
        ids = HmacIdProvider(b"test-key")
        index = SecurePartyIndex.from_plain_graph(
            "p0",
            {"Marlene Dietrich": {"starred_actors": ["A Foreign Affair"]}, "A Foreign Affair": {}},
            {},
            ids,
        )
        semantic = EntitySemanticIndex.from_secure_index(index, ids)
        matching_tokens = set(entity_bucket_tokens(ids, "Foreign Affair", mode="hybrid")) & set(semantic.tokens)

        self.assertTrue(matching_tokens)
        entity_ids = {entity for token in matching_tokens for entity in semantic.entities_for(token)}
        self.assertIn(ids.entity_id("A Foreign Affair"), entity_ids)


if __name__ == "__main__":
    unittest.main()
