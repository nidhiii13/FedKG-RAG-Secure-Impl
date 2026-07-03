import unittest

from src.crypto.dpf import UnconfiguredDpfBackend


class DpfContractTest(unittest.TestCase):
    def test_unconfigured_backend_fails_closed(self):
        backend = UnconfiguredDpfBackend()
        with self.assertRaises(NotImplementedError):
            backend.gen("alpha", 1, ["p0", "p1"])


if __name__ == "__main__":
    unittest.main()
