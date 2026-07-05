"""End-to-end private exact retrieval orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from src.aggregation.private_lookup import PrivateLookupAggregator
from src.aggregation.score_aggregation import MatchScoreShareBuilder
from src.common.types import QueryEdge
from src.crypto.dpf import DpfBackend
from src.crypto.hmac_ids import HmacIdProvider
from src.gateway.query_compiler import ExactQueryCompiler
from src.orchestration.encoded_exact_retriever import EncodedExactRetriever
from src.orchestration.private_universe import build_private_evaluation_universe
from src.orchestration.ranked_evidence import RankedEvidencePipeline
from src.ranking.secure_topk import SecureTopK
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

    def retrieve_ranked(self, query_graph: Sequence[QueryEdge], ranker: SecureTopK, mode: str = "greedy"):
        retrieval = self.retrieve(query_graph, mode=mode)
        share_builder = MatchScoreShareBuilder(share_count=max(2, len(self.parties)))
        ranked = RankedEvidencePipeline(ranker, share_builder=share_builder).run(retrieval["results"], self.final_topk)
        return {
            **retrieval,
            "selected_candidate_ids": ranked.selected_ids,
            "ranked_results": ranked.evidence,
            "aggregated_score_shares": ranked.aggregated_shares,
        }
