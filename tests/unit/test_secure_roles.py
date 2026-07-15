import unittest

from src.runtime.secure_roles import SecureRoleTopology


def local_topology():
    return {
        "local_simulation": True,
        "data_parties": [
            {"role_id": f"p{i}", "authority": f"data-{i}", "endpoint": f"local://p{i}"}
            for i in range(3)
        ],
        "fss_evaluators": [
            {"role_id": f"fss{i}", "authority": f"lookup-{i}", "endpoint": f"local://fss{i}"}
            for i in range(2)
        ],
        "prio_aggregators": [
            {"role_id": f"prio{i}", "authority": f"aggregate-{i}", "endpoint": f"local://prio{i}"}
            for i in range(3)
        ],
    }


class SecureRoleTopologyTest(unittest.TestCase):
    def test_separates_three_data_parties_two_fss_evaluators_and_three_aggregators(self):
        topology = SecureRoleTopology.from_mapping(local_topology())
        self.assertEqual(topology.data_party_ids, ("p0", "p1", "p2"))
        self.assertEqual(topology.fss_evaluator_ids, ("fss0", "fss1"))
        self.assertEqual(topology.prio_aggregator_ids, ("prio0", "prio1", "prio2"))

    def test_rejects_more_than_two_native_fss_evaluators(self):
        payload = local_topology()
        payload["fss_evaluators"].append(
            {"role_id": "fss2", "authority": "lookup-2", "endpoint": "local://fss2"}
        )
        with self.assertRaisesRegex(ValueError, "exactly two evaluator roles"):
            SecureRoleTopology.from_mapping(payload)

    def test_production_requires_independent_fss_authorities(self):
        payload = local_topology()
        payload["local_simulation"] = False
        payload["fss_evaluators"][0]["endpoint"] = "https://fss0.example"
        payload["fss_evaluators"][1]["endpoint"] = "https://fss1.example"
        payload["fss_evaluators"][1]["authority"] = payload["fss_evaluators"][0]["authority"]
        for role in payload["data_parties"] + payload["prio_aggregators"]:
            role["endpoint"] = role["endpoint"].replace("local://", "https://") + ".example"
        with self.assertRaisesRegex(ValueError, "independent authorities"):
            SecureRoleTopology.from_mapping(payload)

    def test_candidate_contributors_must_match_data_parties(self):
        topology = SecureRoleTopology.from_mapping(local_topology())
        with self.assertRaisesRegex(ValueError, "do not match topology"):
            topology.validate_contributor_ids(["p0", "p1"])


if __name__ == "__main__":
    unittest.main()

