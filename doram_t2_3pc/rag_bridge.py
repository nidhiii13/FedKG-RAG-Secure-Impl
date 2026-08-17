"""Bridge from a SimGRAG query graph to the relation-paged MPC retrieval path.

Why this exists
---------------
The project is named for retrieval-augmented generation, and until now every
measurement in ``doram_t2_3pc`` has been cryptographic cost: bytes, rounds,
seconds. No retrieval quality, no answer quality, no language model. That gap is
the first thing a reviewer would name, and this module closes the retrieval half
of it by connecting the existing RAG pipeline to the oblivious backend.

The shapes line up
------------------
SimGRAG's rewrite stage turns a natural-language question into a query graph,
and for MetaQA two-hop questions that graph is already a chain::

    [["Kismet", "acted in", "UNKNOWN"], ["UNKNOWN", "acted in", "A Foreign Affair"]]

which is exactly ``(source, relation_1, relation_2)`` -- the shape
``page_program`` answers. ``query_graph_to_hops`` performs that mapping and
refuses anything it cannot represent, rather than silently mangling it.

What is retrieved, and what is not
----------------------------------
The oblivious backend returns ranked *evidence handles*, not text. Handles are
opaque by construction -- see ``evidence_handles.py`` -- so turning them back
into edges requires a resolver holding the mapping. That resolver is the data
owner, and in a real deployment fetching the evidence is a second protocol this
module does not implement.

For evaluation the resolver is supplied locally, which is sound for measuring
retrieval quality and is **not** a deployment path: it hands the evaluator the
plaintext mapping the servers never see.

Threat model is unchanged. This module runs *outside* the MPC; it prepares the
query and interprets the output, exactly as the client already does.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence


UNKNOWN = "UNKNOWN"
INVERSE_SUFFIX = "_inverse"


def _is_variable(token: str) -> bool:
    """MetaQA writes ``UNKNOWN``; WebQSP writes ``UNKNOWN answer 1`` and
    ``UNKNOWN entity 1``. Both are placeholders for the same thing."""

    return str(token).startswith(UNKNOWN)


@dataclass(frozen=True)
class Hops:
    """A two-hop chain the paged backend can answer."""

    source: str
    relation_1: str
    relation_2: str

    def as_query(self) -> dict[str, str]:
        return {
            "source": self.source,
            "relation_1": self.relation_1,
            "relation_2": self.relation_2,
        }


class UnsupportedQueryGraph(ValueError):
    """The query graph is not a two-hop chain this backend can answer."""


def query_graph_to_hops(query_graph: Sequence[Sequence[str]]) -> Hops:
    """Map a SimGRAG query graph onto ``(source, relation_1, relation_2)``.

    The backend answers one shape: a two-hop path from a concrete anchor,
    through an intermediate, to the answer. Query graphs express that path in
    several orientations, and both datasets in use here do it differently:

    MetaQA emits a forward chain::

        [[s, r1, UNKNOWN], [UNKNOWN, r2, answer]]

    WebQSP frequently reverses the second hop, and sometimes the first::

        [[s, r1, UNKNOWN entity 1], [UNKNOWN answer 1, r2, UNKNOWN entity 1]]
        [[UNKNOWN entity 1, r1, s], [UNKNOWN answer 1, r2, UNKNOWN entity 1]]

    Both are the same path read in a different direction, so each triple is
    normalised to point away from the anchor, appending ``_inverse`` to a
    relation that has to be traversed backwards. That matches how the adjacency
    is built, where every edge is materialised in both directions.

    Raises ``UnsupportedQueryGraph`` for anything that is not a two-hop path.
    That is deliberate: a graph the backend cannot represent must be reported as
    unanswerable rather than approximated, or the evaluation would silently
    credit retrieval that never happened.
    """

    if not isinstance(query_graph, (list, tuple)) or len(query_graph) != 2:
        raise UnsupportedQueryGraph(
            f"expected exactly two triples, got {len(query_graph) if query_graph else 0}"
        )
    triples = []
    for triple in query_graph:
        if not isinstance(triple, (list, tuple)) or len(triple) != 3:
            raise UnsupportedQueryGraph("each element must be a (head, relation, tail) triple")
        triples.append(tuple(str(part) for part in triple))

    def directed(triple, frm):
        """Orient a triple to start at ``frm``, inverting the relation if needed."""

        head, relation, tail = triple
        if head == frm:
            return relation, tail, False
        if tail == frm:
            return relation + INVERSE_SUFFIX, head, True
        return None

    # Enumerate every two-hop path: start at a concrete entity, step to a
    # variable, step onward. The final endpoint may be concrete (MetaQA writes
    # the answer entity there) or another variable (WebQSP writes a placeholder);
    # either way the backend only needs the anchor and the two relations.
    candidates = []
    for first, second in (triples, triples[::-1]):
        for anchor in (first[0], first[2]):
            if _is_variable(anchor):
                continue
            step = directed(first, anchor)
            if step is None:
                continue
            relation_1, middle, inverted_1 = step
            if not _is_variable(middle):
                continue
            onward = directed(second, middle)
            if onward is None:
                continue
            relation_2, endpoint, _ = onward
            if endpoint == middle:
                continue
            candidates.append((inverted_1, Hops(anchor, relation_1, relation_2)))

    if not candidates:
        raise UnsupportedQueryGraph(
            "the two triples do not form a two-hop path from a concrete entity"
        )
    # A graph with two concrete entities admits the path in both directions.
    # Prefer the one whose first hop needs no inversion, which is the direction
    # the question was asked in.
    candidates.sort(key=lambda item: item[0])
    return candidates[0][1]


def build_handle_resolver(
    owner_edges: dict[str, list[dict[str, Any]]],
) -> dict[int, dict[str, Any]]:
    """Map evidence handle -> edge, for turning retrieval output into text.

    **Evaluation only.** In deployment the owners hold this mapping and the
    servers never see it; constructing it here means the evaluator is trusted
    with plaintext the protocol is designed to withhold.
    """

    resolver: dict[int, dict[str, Any]] = {}
    for owner, edges in owner_edges.items():
        for edge in edges:
            handle = edge.get("evidence")
            if handle:
                resolver[int(handle)] = {**edge, "owner": owner}
    return resolver


def rows_to_evidence(
    rows: list[dict[str, int]],
    resolver: dict[int, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Turn the backend's ranked rows into the evidence shape the RAG runner uses.

    The runner expects ``{"score", "edges", "reuse_nodes"}`` per item, and scores
    evidence by substring match against the ground truth, so the edges must carry
    entity names rather than internal ids.

    Invalid rows -- padding the circuit emits to keep its output width fixed --
    are dropped here rather than surfaced as empty evidence.
    """

    evidence: list[dict[str, Any]] = []
    for row in rows:
        if not row.get("valid"):
            continue
        edges = []
        for key in ("left_evidence", "right_evidence"):
            handle = row.get(key)
            found = resolver.get(int(handle)) if handle else None
            if found is not None:
                edges.append([found["source"], found["relation"], found["target"]])
        if edges:
            evidence.append(
                {"score": row.get("score", 0), "edges": edges, "reuse_nodes": []}
            )
    return evidence


def evidence_hit(evidence: list[dict[str, Any]], groundtruths: list[str]) -> bool:
    """Whether retrieved evidence contains a ground-truth answer.

    Matches ``scripts/run_private_frontier_batch._evidence_hit`` so numbers from
    this path are comparable with the existing RAG runner's.
    """

    import json

    if not groundtruths:
        return False
    payload = json.dumps(evidence, ensure_ascii=False).casefold()
    return any(str(answer).casefold() in payload for answer in groundtruths)
