import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = REPO_ROOT / "mpspdz_client_excluded" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from bucketed_oram_limb_index import (  # noqa: E402
    ID_LIMBS,
    build_party_index,
    directory_slot_limb,
    hmac_limbs,
    probe_slots,
)


class BucketedOramLimbIndexTest(unittest.TestCase):
    def test_directory_resolves_query_with_128_bit_ids(self):
        key = "test-key"
        graph = {"Kismet": {"starred_actors": ["Marlene Dietrich"]}}
        index = build_party_index(
            graph,
            key,
            allowed_relations={"starred_actors"},
            read_padding=4,
        )
        self.assertEqual(index["id_limbs"], ID_LIMBS)
        source_id = hmac_limbs(key, "entity", "Kismet")
        relation_id = hmac_limbs(key, "relation", "starred_actors")
        capacity = len(index["source_directory"])
        base = directory_slot_limb(key, "source", 0, source_id, relation_id, capacity)

        entry = None
        for slot in probe_slots(base, capacity, index["stats"]["source_probe_limit"]):
            candidate = index["source_directory"][slot]
            if candidate[11] and tuple(candidate[:4]) == source_id and tuple(candidate[4:8]) == relation_id:
                entry = candidate
                break
        self.assertIsNotNone(entry)
        offset, count = entry[9], entry[10]
        self.assertEqual(count, 1)
        edge = index["source_edges"][offset]
        self.assertEqual(tuple(edge[:4]), source_id)
        self.assertEqual(tuple(edge[4:8]), relation_id)
        self.assertEqual(tuple(edge[8:12]), hmac_limbs(key, "entity", "Marlene Dietrich"))
        self.assertIn(str(edge[12]), index["evidence_vault"])


if __name__ == "__main__":
    unittest.main()
