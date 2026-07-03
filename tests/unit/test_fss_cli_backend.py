import sys
import tempfile
import unittest
from pathlib import Path

from src.crypto.fss_cli_backend import FssCliBackend, FssCliBackendError


class FssCliBackendTest(unittest.TestCase):
    def test_missing_cli_fails(self):
        backend = FssCliBackend(("/definitely/missing/fss-cli",))
        with self.assertRaises(FssCliBackendError):
            backend.gen("alpha", 1, ["p0", "p1"])

    def test_cli_protocol_roundtrip_with_stub_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            stub = Path(tmp) / "stub_cli.py"
            stub.write_text(
                """import json, sys
req = json.loads(sys.stdin.read())
if req["op"] == "gen":
    print(json.dumps({"shares": {p: {"p": p, "alpha": req["alpha"]} for p in req["party_ids"]}}))
elif req["op"] == "eval":
    print(json.dumps({"value": int(req["share"]["alpha"] == req["point"])}))
"""
            )
            backend = FssCliBackend((sys.executable, str(stub)))
            shares = backend.gen("abc", 1, ["p0", "p1"])
            self.assertEqual(set(shares), {"p0", "p1"})
            self.assertEqual(backend.eval(shares["p0"], "abc"), 1)
            self.assertEqual(backend.eval(shares["p0"], "xyz"), 0)


if __name__ == "__main__":
    unittest.main()
