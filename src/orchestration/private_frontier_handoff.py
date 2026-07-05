"""DPF/FSS-based opaque frontier handoff plumbing.

A frontier token represents an intermediate entity that may let another party
continue a multi-hop path. The token is HMAC-derived and DPF-shared; parties
evaluate shares over their local frontier indexes. The current coordinator
reconstructs matched opaque frontier tokens, but not plaintext entity labels or
final party ownership. A production version should also pad/batch handoffs and
avoid exposing token-linkage patterns.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, Mapping, Sequence

from src.crypto.dpf import DpfBackend, DpfKeyShare
from src.crypto.dpf_domain import DPF_MODULUS
from src.party.frontier_index import FrontierIndex


@dataclass(frozen=True)
class FrontierHandoffRequest:
    request_id: str
    key_shares: Mapping[str, DpfKeyShare]


@dataclass(frozen=True)
class FrontierEvalShares:
    party_id: str
    request_id: str
    eval_shares: Dict[str, int]


@dataclass(frozen=True)
class FrontierMatch:
    request_id: str
    frontier_token: str


@dataclass(frozen=True)
class PrivateFrontierHandoff:
    backend: DpfBackend
    party_ids: Sequence[str]
    modulus: int = DPF_MODULUS

    def create_request(self, request_id: str, token: str) -> FrontierHandoffRequest:
        return FrontierHandoffRequest(
            request_id=request_id,
            key_shares=self.backend.gen(token, beta=1, party_ids=self.party_ids),
        )

    def evaluate(
        self,
        party_id: str,
        frontier_index: FrontierIndex,
        request: FrontierHandoffRequest,
        points: Sequence[str] | None = None,
    ) -> FrontierEvalShares:
        key_share = request.key_shares[party_id]
        points = list(points) if points is not None else frontier_index.tokens
        eval_many = getattr(self.backend, "eval_many", None)
        if callable(eval_many):
            values = eval_many(key_share, points)
        else:
            values = [self.backend.eval(key_share, point) for point in points]
        return FrontierEvalShares(
            party_id=party_id,
            request_id=request.request_id,
            eval_shares=dict(zip(points, values)),
        )

    def reconstruct(self, eval_batches: Iterable[FrontierEvalShares]) -> list[FrontierMatch]:
        by_request: Dict[str, Dict[str, FrontierEvalShares]] = {}
        for batch in eval_batches:
            by_request.setdefault(batch.request_id, {})[batch.party_id] = batch

        matches: list[FrontierMatch] = []
        for request_id, party_batches in by_request.items():
            missing = set(self.party_ids) - set(party_batches)
            if missing:
                raise ValueError(f"Missing frontier eval shares for parties: {sorted(missing)}")
            candidate_tokens = set()
            for batch in party_batches.values():
                candidate_tokens.update(batch.eval_shares)
            for token in candidate_tokens:
                values = []
                for party_id in self.party_ids:
                    party_values = party_batches[party_id].eval_shares
                    if token not in party_values:
                        break
                    values.append(party_values[token])
                else:
                    if sum(values) % self.modulus != 0:
                        matches.append(FrontierMatch(request_id=request_id, frontier_token=token))
        return matches
