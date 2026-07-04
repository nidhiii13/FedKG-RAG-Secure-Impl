"""End-to-end private exact retrieval orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from src.aggregation.private_lookup import PrivateLookupAggregator
from src.common.types import QueryEdge
from src.crypto.dpf import DpfBackend
from src.crypto.hmac_ids import HmacIdProvider
from src.gateway.query_compiler import ExactQueryCompiler
from src.orchestration.encoded_exact_retriever import EncodedExactRetriever
from src.orchestration.private_universe import build_private_evaluation_universe
from src.party.private_evaluator import PrivatePartyEvaluator
from src.party.secure_index import SecurePartyIndex


@dataclass
class PrivateExactRetriever:
    parties: Sequence[SecurePartyIndex]
    ids: HmacIdProvider
    backend: DpfBackend
    final_topk: int = 3

    def retrieve(self, query_graph: Sequence[QueryEdge], mode: str = "greedy"):
        party_ids = [party.party_id for party in self.parties]
        compiler = ExactQueryCompiler(self.ids)
        private_shares = compiler.compile_private_shares(query_graph, party_ids, self.backend)
        universe = build_private_evaluation_universe(query_graph, self.parties)

        eval_shares = [
            PrivatePartyEvaluator(party, self.backend).evaluate(private_shares[party.party_id], universe)
            for party in self.parties
        ]
        candidates = PrivateLookupAggregator(party_ids).aggregate(eval_shares)
        return EncodedExactRetriever(self.parties, final_topk=self.final_topk).retrieve_from_candidates(
            query_graph,
            candidates,
            mode=mode,
        )
