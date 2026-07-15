import unittest
from pathlib import Path

from src.aggregation.prio3_backend import Prio3LocalBackend
from src.aggregation.prio3_types import Prio3SumVecRequest


class NativePrio3CliIntegrationTest(unittest.TestCase):
    def test_three_aggregator_sum_vec(self):
        executable = Path("tools/prio3_cli/target/release/fedkg-prio3-cli")
        if not executable.exists():
            self.skipTest("native Prio3 CLI is not built")

        backend = Prio3LocalBackend.from_executable(executable)
        capabilities = backend.capabilities()
        self.assertEqual(capabilities["implementation"], "libprio-rs/prio3")
        self.assertTrue(capabilities["local_reconstruction"])

        result = backend.sum_vec(
            Prio3SumVecRequest(
                measurements=[[1, 2, 1], [3, 4, 0], [5, 6, 1]],
                aggregator_count=3,
                bits=8,
                context="fedkg-rag/test/three-aggregators",
            )
        )
        self.assertEqual(result.aggregate, [9, 12, 2])


if __name__ == "__main__":
    unittest.main()

