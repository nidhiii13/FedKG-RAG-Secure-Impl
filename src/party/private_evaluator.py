"""Party-side DPF/FSS evaluation over HMAC indexes.

A real DPF eval output is a share, not a local match bit. This evaluator
therefore returns raw per-point eval shares. Match decisions happen only after
all configured party shares are reconstructed by `PrivateLookupAggregator`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

from src.common.types import PrivateEvaluationUniverse, PrivatePartyEvalShares, PrivateQueryShare
from src.crypto.dpf import DpfBackend
from src.party.secure_index import SecurePartyIndex


@dataclass
class PrivatePartyEvaluator:
    index: SecurePartyIndex
    backend: DpfBackend

    def evaluate(
        self,
        share: PrivateQueryShare,
        universe: PrivateEvaluationUniverse | None = None,
    ) -> PrivatePartyEvalShares:
        if share.party_id != self.index.party_id:
            raise ValueError(
                f"Share for {share.party_id} cannot be evaluated by party {self.index.party_id}"
            )

        node_eval_shares: Dict[str, Dict[str, int]] = {}
        for query_node, key_share in share.node_key_shares.items():
            points = universe.node_points.get(query_node, []) if universe else self.index.display_entities.keys()
            node_eval_shares[query_node] = {
                encoded_entity: self.backend.eval(key_share, encoded_entity)
                for encoded_entity in points
            }

        type_eval_shares: Dict[str, Dict[str, int]] = {}
        for unknown_node, key_share in share.type_key_shares.items():
            points = universe.type_points.get(unknown_node, []) if universe else self.index.type_index.keys()
            type_eval_shares[unknown_node] = {
                encoded_type: self.backend.eval(key_share, encoded_type)
                for encoded_type in points
            }

        relation_eval_shares: Dict[str, Dict[str, int]] = {}
        for query_relation, key_share in share.relation_key_shares.items():
            points = universe.relation_points.get(query_relation, []) if universe else self.index.local_relations
            relation_eval_shares[query_relation] = {
                encoded_relation: self.backend.eval(key_share, encoded_relation)
                for encoded_relation in points
            }

        return PrivatePartyEvalShares(
            party_id=self.index.party_id,
            node_eval_shares=node_eval_shares,
            relation_eval_shares=relation_eval_shares,
            type_eval_shares=type_eval_shares,
            local_entity_points=sorted(self.index.display_entities),
            local_relation_points=sorted(self.index.local_relations),
            type_members={type_id: list(nodes) for type_id, nodes in self.index.type_index.items()},
        )
