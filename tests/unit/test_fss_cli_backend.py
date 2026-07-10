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
    print(json.dumps({"shares": [{"party": i, "alpha": req["alpha"]} for i in range(req["share_count"])]}))
elif req["op"] == "eval":
    print(json.dumps({"value": int(req["share"]["alpha"] == req["point"])}))
elif req["op"] == "eval_many":
    print(json.dumps({"values": [int(req["share"]["alpha"] == point) for point in req["points"]]}))
"""
            )
            backend = FssCliBackend((sys.executable, str(stub)))
            shares = backend.gen("abc", 1, ["p0", "p1"])
            self.assertEqual(set(shares), {"p0", "p1"})
            self.assertEqual(backend.eval(shares["p0"], "abc"), 1)
            self.assertEqual(backend.eval(shares["p0"], "xyz"), 0)
            self.assertEqual(backend.eval_many(shares["p0"], ["abc", "xyz", "abc"]), [1, 0, 1])

    def test_eval_many_chunks_large_requests(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "calls.txt"
            stub = Path(tmp) / "stub_cli.py"
            stub.write_text(
                f"""import json, sys
from pathlib import Path
req = json.loads(sys.stdin.read())
if req["op"] == "eval_many":
    with Path({str(log)!r}).open("a") as handle:
        handle.write(str(len(req["points"])) + "\\n")
    print(json.dumps({{"values": [len(point) for point in req["points"]]}}))
"""
            )
            backend = FssCliBackend((sys.executable, str(stub)), max_eval_batch_size=2)
            values = backend.eval_many(type("Share", (), {"payload": {}})(), ["a", "bb", "ccc", "dddd", "eeeee"])

            self.assertEqual(values, [1, 2, 3, 4, 5])
            self.assertEqual(log.read_text().splitlines(), ["2", "2", "1"])

    def test_eval_many_retries_smaller_batches_after_cli_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "calls.txt"
            stub = Path(tmp) / "stub_cli.py"
            stub.write_text(
                f"""import json, os, signal, sys
from pathlib import Path
req = json.loads(sys.stdin.read())
if req["op"] == "eval_many":
    with Path({str(log)!r}).open("a") as handle:
        handle.write(str(len(req["points"])) + "\\n")
    if len(req["points"]) > 2:
        os.kill(os.getpid(), signal.SIGSEGV)
    print(json.dumps({{"values": [len(point) for point in req["points"]]}}))
"""
            )
            backend = FssCliBackend((sys.executable, str(stub)), max_eval_batch_size=4)
            values = backend.eval_many(type("Share", (), {"payload": {}})(), ["a", "bb", "ccc", "dddd"])

            self.assertEqual(values, [1, 2, 3, 4])
            self.assertEqual(log.read_text().splitlines(), ["4", "2", "2"])


if __name__ == "__main__":
    unittest.main()
