"""Reconstruct private lookup results from party DPF eval shares."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, Mapping, Sequence

from src.common.types import EntityRef, PrivatePartyEvalShares, RelationRef, SecurePartyCandidates
from src.crypto.dpf_domain import DPF_MODULUS

@dataclass(frozen=True)
class PrivateLookupAggregator:
    party_ids: Sequence[str]
    modulus: int = DPF_MODULUS

    def aggregate(self, party_shares: Iterable[PrivatePartyEvalShares]) -> SecurePartyCandidates:
        by_party = {share.party_id: share for share in party_shares}
        missing = set(self.party_ids) - set(by_party)
        if missing:
            raise ValueError(f"Missing DPF eval shares for parties: {sorted(missing)}")

        nodes: Dict[str, Dict[EntityRef, float] | None] = {}
        for label in self._labels(by_party.values(), "node_eval_shares"):
            nodes[label] = self._aggregate_points(
                by_party,
                label,
                "node_eval_shares",
                lambda party_id, point: EntityRef(party_id, point),
            )

        for label in self._labels(by_party.values(), "type_eval_shares"):
            matched_types = self._matched_points(by_party, label, "type_eval_shares")
            matches: Dict[EntityRef, float] = {}
            for party_id in self.party_ids:
                share = by_party[party_id]
                for type_id in matched_types:
                    for entity_id in share.type_members.get(type_id, []):
                        matches[EntityRef(party_id, entity_id)] = 0.0
            nodes[label] = matches

        relations: Dict[str, Dict[RelationRef, float]] = {}
        for label in self._labels(by_party.values(), "relation_eval_shares"):
            relations[label] = self._aggregate_points(
                by_party,
                label,
                "relation_eval_shares",
                lambda party_id, point: RelationRef(party_id, point),
            )

        return SecurePartyCandidates(nodes=nodes, relations=relations)

    def _aggregate_points(
        self,
        by_party: Mapping[str, PrivatePartyEvalShares],
        label: str,
        attr: str,
        ref_factory,
    ):
        matched_points = self._matched_points(by_party, label, attr)
        out = {}
        ownership_attr = "local_relation_points" if attr == "relation_eval_shares" else "local_entity_points"
        for party_id in self.party_ids:
            owned_points = set(getattr(by_party[party_id], ownership_attr))
            for point in matched_points:
                if point in owned_points:
                    out[ref_factory(party_id, point)] = 0.0
        return out

    def _matched_points(
        self,
        by_party: Mapping[str, PrivatePartyEvalShares],
        label: str,
        attr: str,
    ) -> set[str]:
        candidate_points = set()
        for party_id in self.party_ids:
            candidate_points.update(getattr(by_party[party_id], attr).get(label, {}))

        matched = set()
        for point in candidate_points:
            values = []
            for party_id in self.party_ids:
                party_values = getattr(by_party[party_id], attr).get(label, {})
                if point not in party_values:
                    break
                values.append(party_values[point])
            else:
                if sum(values) % self.modulus != 0:
                    matched.add(point)
        return matched

    @staticmethod
    def _labels(shares: Iterable[PrivatePartyEvalShares], attr: str) -> list[str]:
        labels = []
        seen = set()
        for share in shares:
            for label in getattr(share, attr):
                if label not in seen:
                    labels.append(label)
                    seen.add(label)
        return labels
