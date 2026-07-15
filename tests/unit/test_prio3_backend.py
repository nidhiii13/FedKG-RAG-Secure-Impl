import sys
import tempfile
import unittest
from pathlib import Path

from src.aggregation.prio3_backend import Prio3BackendError, Prio3LocalBackend
from src.aggregation.prio3_types import Prio3SumVecRequest


class Prio3LocalBackendTest(unittest.TestCase):
    def test_request_validation(self):
        with self.assertRaises(ValueError):
            Prio3SumVecRequest([[1]], aggregator_count=1, bits=8).validate()
        with self.assertRaises(ValueError):
            Prio3SumVecRequest([[256]], aggregator_count=3, bits=8).validate()
        with self.assertRaises(ValueError):
            Prio3SumVecRequest([[1], [1, 2]], aggregator_count=3, bits=8).validate()

    def test_three_aggregator_cli_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            stub = Path(tmp) / "prio_stub.py"
            stub.write_text(
                """import json, sys
request = json.loads(sys.stdin.read())
if request["op"] == "sum_vec":
    aggregate = [sum(column) for column in zip(*request["measurements"])]
    print(json.dumps({
        "aggregate": aggregate,
        "aggregator_count": request["aggregator_count"],
        "report_count": len(request["measurements"]),
    }))
"""
            )
            backend = Prio3LocalBackend((sys.executable, str(stub)))
            result = backend.sum_vec(
                Prio3SumVecRequest([[1, 2], [3, 4], [5, 6]], aggregator_count=3, bits=8)
            )
            self.assertEqual(result.aggregate, [9, 12])
            self.assertEqual(result.aggregator_count, 3)
            self.assertEqual(result.report_count, 3)

    def test_missing_cli_fails(self):
        backend = Prio3LocalBackend(("/definitely/missing/prio3-cli",))
        with self.assertRaises(Prio3BackendError):
            backend.capabilities()


if __name__ == "__main__":
    unittest.main()

