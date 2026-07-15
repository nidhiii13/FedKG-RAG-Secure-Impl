"""Plan an undirected query path for directed frontier execution.

Query-graph topology is public at the gateway, so it can be reordered without
touching private party data.  Relation direction is retained separately: when
the path is traversed from an edge's target to its source, ``reverse`` is true
and the party must use its incoming-relation index.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from src.common.normalization import is_unknown
from src.common.types import QueryEdge


@dataclass(frozen=True)
class PlannedQueryEdge:
    """One query edge oriented for traversal from ``source`` to ``target``."""

    source: str
    relation: str
    target: str
    reverse: bool = False

    @property
    def edge(self) -> QueryEdge:
        return (self.source, self.relation, self.target)


def plan_query_path(query_graph: Sequence[QueryEdge]) -> list[PlannedQueryEdge]:
    """Return a deterministic, anchor-first traversal of a path-shaped graph.

    The input triples retain their directed meaning.  Only their traversal
    order/orientation changes.  The current secure frontier protocol needs a
    known entity at a path endpoint, except that a known entity may anchor a
    simple closed path.  Branches, disconnected graphs and fully unknown paths
    require a more general secure join protocol.
    """

    edges = [_validated_edge(edge) for edge in query_graph]
    if not edges:
        return []

    incident: dict[str, list[int]] = {}
    node_order: list[str] = []
    for index, (source, _, target) in enumerate(edges):
        for node in (source, target):
            if node not in incident:
                incident[node] = []
                node_order.append(node)
            incident[node].append(index)

    if any(len(indexes) > 2 for indexes in incident.values()):
        raise ValueError("frontier handoff currently supports path-shaped query graphs, not branches")

    endpoints = {node for node, indexes in incident.items() if len(indexes) == 1}
    anchor = next((node for node in node_order if node in endpoints and not is_unknown(node)), None)
    if anchor is None:
        if not any(not is_unknown(node) for node in node_order):
            raise ValueError("frontier handoff requires at least one known entity anchor")
        if endpoints:
            raise ValueError("frontier handoff requires a known entity at a query-path endpoint")
        anchor = next(node for node in node_order if not is_unknown(node))

    planned: list[PlannedQueryEdge] = []
    used: set[int] = set()
    current = anchor
    while len(used) < len(edges):
        choices = [index for index in incident[current] if index not in used]
        if not choices:
            break
        if len(choices) > 1:
            # A simple cycle has two choices only at its anchor.  Input order is
            # public and gives us a stable direction around that cycle.
            choices.sort()

        edge_index = choices[0]
        source, relation, target = edges[edge_index]
        if current == source:
            planned.append(PlannedQueryEdge(source, relation, target, reverse=False))
            current = target
        else:
            planned.append(PlannedQueryEdge(target, relation, source, reverse=True))
            current = source
        used.add(edge_index)

    if len(used) != len(edges):
        raise ValueError("frontier handoff requires one connected query path or simple cycle")
    return planned


def _validated_edge(edge: QueryEdge) -> QueryEdge:
    if len(edge) != 3:
        raise ValueError("each query edge must contain exactly source, relation and target")
    source, relation, target = (str(value) for value in edge)
    if not source or not relation or not target:
        raise ValueError("query edge values must be non-empty")
    if source == target:
        raise ValueError("self-loop query edges are not supported by frontier handoff")
    return source, relation, target
