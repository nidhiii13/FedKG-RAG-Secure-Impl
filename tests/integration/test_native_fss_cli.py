import unittest
from pathlib import Path

from src.crypto.fss_cli_backend import FssCliBackend


class NativeFssCliIntegrationTest(unittest.TestCase):
    def test_native_dpf_gen_eval_reconstructs_point_function(self):
        executable = Path("build/fss_cli/fedkg-fss-cli")
        if not executable.exists():
            self.skipTest("native FSS CLI is not built")

        backend = FssCliBackend.from_executable(executable)
        shares = backend.gen("000000000000002a", 1, ["p0", "p1"])

        modulus = 1 << 64
        at_alpha = (
            backend.eval(shares["p0"], "000000000000002a")
            + backend.eval(shares["p1"], "000000000000002a")
        ) % modulus
        away_from_alpha = (
            backend.eval(shares["p0"], "0000000000000064")
            + backend.eval(shares["p1"], "0000000000000064")
        ) % modulus
        p0_many = backend.eval_many(shares["p0"], ["000000000000002a", "0000000000000064"])
        p1_many = backend.eval_many(shares["p1"], ["000000000000002a", "0000000000000064"])

        self.assertEqual(at_alpha, 1)
        self.assertEqual(away_from_alpha, 0)
        self.assertEqual((p0_many[0] + p1_many[0]) % modulus, 1)
        self.assertEqual((p0_many[1] + p1_many[1]) % modulus, 0)


if __name__ == "__main__":
    unittest.main()
