#!/usr/bin/env python3
"""Serve one multi-party FSS evaluator over localhost TCP (evaluation only).

One process = one evaluator role, loaded once from its replicated store,
answering length-prefixed JSON requests (multiparty_fss/transport.py). Every
request is validated by the same fail-closed wire layer as the offline tools;
failures return {"error": ...} and never partial results.

This transport has no confidentiality or authentication — see the security
note in multiparty_fss/transport.py. It exists to measure real
process-separated end-to-end costs.

Prints one line "READY <port>" to stdout once listening.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from multiparty_fss.errors import MultipartyFssError
from multiparty_fss.requests import MpFssEvaluatorRequest
from multiparty_fss.service import (
    MultipartyFssEvaluatorService,
    MultipartyFssEvaluatorStore,
)
from multiparty_fss.transport import recv_message, send_message


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--store", required=True, type=Path)
    parser.add_argument("--evaluator-id", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0, help="0 = ephemeral")
    parser.add_argument(
        "--max-requests", type=int, default=0, help="exit after this many (0 = serve forever)"
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    store = MultipartyFssEvaluatorStore.load(
        args.store, expected_evaluator_id=args.evaluator_id
    )
    service = MultipartyFssEvaluatorService(store)
    # Warm the per-domain universe caches so steady-state timing is measured.
    for domain in ("entity", "relation"):
        try:
            store.universe(domain)
        except MultipartyFssError:
            pass

    listener = socket.create_server((args.host, args.port))
    listener.listen(16)
    print(f"READY {listener.getsockname()[1]}", flush=True)
    served = 0
    while True:
        connection, _ = listener.accept()
        with connection:
            try:
                payload = recv_message(connection)
                request = MpFssEvaluatorRequest.from_dict(payload)
                response = service.evaluate(request)
                send_message(connection, response.to_dict())
            except MultipartyFssError as exc:
                try:
                    send_message(connection, {"error": str(exc)})
                except OSError:
                    pass
            except (json.JSONDecodeError, OSError) as exc:
                try:
                    send_message(connection, {"error": f"transport failure: {exc}"})
                except OSError:
                    pass
        served += 1
        if args.max_requests and served >= args.max_requests:
            return 0


if __name__ == "__main__":
    raise SystemExit(main())
