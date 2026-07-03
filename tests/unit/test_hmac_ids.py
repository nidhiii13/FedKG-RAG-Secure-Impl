import unittest

from src.crypto.hmac_ids import HmacIdProvider


class HmacIdProviderTest(unittest.TestCase):
    def test_ids_are_stable_and_namespaced(self):
        ids = HmacIdProvider(b"test-key")
        self.assertEqual(ids.entity_id(" Tom   Hanks "), ids.entity_id("tom hanks"))
        self.assertNotEqual(ids.entity_id("acted in"), ids.relation_id("acted in"))


if __name__ == "__main__":
    unittest.main()
