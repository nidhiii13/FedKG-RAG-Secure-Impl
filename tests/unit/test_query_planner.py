import unittest

from src.gateway.query_planner import plan_query_path


class QueryPlannerTest(unittest.TestCase):
    def test_reorders_and_orients_zig_zag_path_from_known_endpoint(self):
        planned = plan_query_path(
            [
                ("UNKNOWN middle 1", "relation_b", "Known target"),
                ("Known source", "relation_a", "UNKNOWN middle 1"),
            ]
        )

        self.assertEqual(
            [(edge.edge, edge.reverse) for edge in planned],
            [
                (("Known target", "relation_b", "UNKNOWN middle 1"), True),
                (("UNKNOWN middle 1", "relation_a", "Known source"), True),
            ],
        )

    def test_rejects_branch_until_secure_join_protocol_supports_it(self):
        with self.assertRaisesRegex(ValueError, "not branches"):
            plan_query_path(
                [
                    ("Known", "r1", "UNKNOWN center"),
                    ("UNKNOWN center", "r2", "UNKNOWN left"),
                    ("UNKNOWN center", "r3", "UNKNOWN right"),
                ]
            )

    def test_requires_known_endpoint_anchor(self):
        with self.assertRaisesRegex(ValueError, "known entity at a query-path endpoint"):
            plan_query_path(
                [
                    ("UNKNOWN left", "r1", "Known center"),
                    ("Known center", "r2", "UNKNOWN right"),
                ]
            )

    def test_known_entity_can_anchor_closed_redundant_constraint(self):
        planned = plan_query_path(
            [
                ("Known actor", "acted_in", "UNKNOWN film 1"),
                ("UNKNOWN film 1", "has_actor", "Known actor"),
            ]
        )

        self.assertEqual(
            [(edge.edge, edge.reverse) for edge in planned],
            [
                (("Known actor", "acted_in", "UNKNOWN film 1"), False),
                (("UNKNOWN film 1", "has_actor", "Known actor"), False),
            ],
        )


if __name__ == "__main__":
    unittest.main()
