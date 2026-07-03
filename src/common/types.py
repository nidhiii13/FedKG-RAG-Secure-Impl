"""Protocol datatypes for secure exact retrieval."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

QueryEdge = Tuple[str, str, str]
EncodedId = str


@dataclass(frozen=True, order=True)
class EntityRef:
    party_id: str
    entity_id: EncodedId


@dataclass(frozen=True, order=True)
class RelationRef:
    party_id: str
    relation_id: EncodedId


@dataclass(frozen=True)
class LocalExpansion:
    source: EntityRef
    relation: RelationRef
    target: EntityRef


@dataclass
class SecurePartyCandidates:
    nodes: Dict[str, Optional[Dict[EntityRef, float]]]
    relations: Dict[str, Dict[RelationRef, float]]


@dataclass
class MatchResult:
    score: float
    edges: List[Tuple[str, str, str]]
    reuse_nodes: bool
    parties: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class ExactQueryIds:
    node_ids: Dict[str, EncodedId]
    relation_ids: Dict[str, EncodedId]
    type_ids: Dict[str, EncodedId]


@dataclass(frozen=True)
class PrivateQueryShare:
    party_id: str
    query_shape: Sequence[QueryEdge]
    node_key_shares: Dict[str, object]
    relation_key_shares: Dict[str, object]
    type_key_shares: Dict[str, object]


@dataclass
class PrivateEvaluationUniverse:
    node_points: Dict[str, List[EncodedId]]
    relation_points: Dict[str, List[EncodedId]]
    type_points: Dict[str, List[EncodedId]]


@dataclass
class PrivatePartyEvalShares:
    party_id: str
    node_eval_shares: Dict[str, Dict[EncodedId, int]]
    relation_eval_shares: Dict[str, Dict[EncodedId, int]]
    type_eval_shares: Dict[str, Dict[EncodedId, int]]
    local_entity_points: List[EncodedId] = field(default_factory=list)
    local_relation_points: List[EncodedId] = field(default_factory=list)
    type_members: Dict[EncodedId, List[EncodedId]] = field(default_factory=dict)
