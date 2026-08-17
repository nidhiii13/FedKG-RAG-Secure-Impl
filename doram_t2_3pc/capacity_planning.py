"""Raw-dataset degree statistics and layout capacity planning.

This module deliberately operates on *raw*, unbounded owner edge lists. It
never enforces ``fanout_per_owner`` or ``relation_fanout_per_owner``, so it can
measure a dataset that the current packed scan layout cannot represent. That is
the point: the packed layout fails closed on overflow, so an owner needs a way
to discover the required capacity, and the resulting truncation cost, *before*
choosing public bounds.

Nothing produced here may be sent to the computation servers by default.
Realized degree maxima are part of an owner's private degree profile unless the
deployment explicitly declares those bounds public. The public configuration
only ever carries the declared bounds, never the realized ones.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterable, Sequence


REQUIRED_EDGE_KEYS = ("source", "relation", "target")


def _edge_triples(edges: Iterable[Any]) -> list[tuple[str, str, str]]:
    """Return (source, relation, target) triples from a raw owner edge list.

    Extra keys such as ``evidence``/``score`` are ignored so that a dataset can
    be profiled before handles and scores have been assigned.
    """

    triples: list[tuple[str, str, str]] = []
    for row_number, edge in enumerate(edges, start=1):
        if not isinstance(edge, dict):
            raise ValueError(f"edge {row_number} must be a JSON object")
        missing = [key for key in REQUIRED_EDGE_KEYS if key not in edge]
        if missing:
            raise ValueError(
                f"edge {row_number} is missing required key(s): "
                + ", ".join(missing)
            )
        values = []
        for key in REQUIRED_EDGE_KEYS:
            value = edge[key]
            if not isinstance(value, str) or not value:
                raise ValueError(
                    f"edge {row_number} field {key!r} must be a non-empty string"
                )
            values.append(value)
        triples.append((values[0], values[1], values[2]))
    return triples


def _percentiles(
    values: Sequence[int], points: Sequence[float] = (0.5, 0.9, 0.99, 0.999)
) -> dict[str, int]:
    """Nearest-rank percentiles; exact and dependency-free."""

    if not values:
        return {f"p{point:g}": 0 for point in points}
    ordered = sorted(values)
    result = {}
    for point in points:
        if not 0.0 < point <= 1.0:
            raise ValueError("percentile points must be in (0, 1]")
        rank = max(1, min(len(ordered), -(-int(point * len(ordered) * 1000) // 1000)))
        result[f"p{point:g}"] = ordered[rank - 1]
    return result


def degree_profile(edges: Iterable[Any]) -> dict[str, Any]:
    """Measure source and (source, relation) degree structure of raw edges."""

    triples = _edge_triples(edges)
    source_counts: Counter[str] = Counter()
    key_counts: Counter[tuple[str, str]] = Counter()
    relation_counts: Counter[str] = Counter()
    for source, relation, _ in triples:
        source_counts[source] += 1
        key_counts[(source, relation)] += 1
        relation_counts[relation] += 1

    source_degrees = list(source_counts.values())
    key_degrees = list(key_counts.values())
    duplicate_triples = len(triples) - len(set(triples))
    return {
        "edge_count": len(triples),
        "duplicate_triple_count": duplicate_triples,
        "distinct_sources": len(source_counts),
        "distinct_relations": len(relation_counts),
        "distinct_source_relation_keys": len(key_counts),
        "max_source_degree": max(source_degrees, default=0),
        "max_source_relation_degree": max(key_degrees, default=0),
        "mean_source_degree": (
            len(triples) / len(source_counts) if source_counts else 0.0
        ),
        "mean_source_relation_degree": (
            len(triples) / len(key_counts) if key_counts else 0.0
        ),
        "source_degree_percentiles": _percentiles(source_degrees),
        "source_relation_degree_percentiles": _percentiles(key_degrees),
        # The ratio the relation-paged layout exploits: indexing by
        # (source, relation) instead of source alone shrinks the widest bucket
        # by this factor.
        "relation_split_reduction_factor": (
            max(source_degrees, default=0) / max(key_degrees, default=1)
            if key_degrees
            else 0.0
        ),
    }


def bound_overflow(
    edges: Iterable[Any],
    *,
    fanout_per_owner: int,
    relation_fanout_per_owner: int | None = None,
) -> dict[str, Any]:
    """Report exactly what the current packed scan layout would reject.

    The packed preparer fails closed rather than truncating, so these counts
    describe the edges a dataset builder would have to drop to make the file
    representable at the supplied bounds.
    """

    if fanout_per_owner < 1:
        raise ValueError("fanout_per_owner must be positive")
    if relation_fanout_per_owner is not None and relation_fanout_per_owner < 1:
        raise ValueError("relation_fanout_per_owner must be positive")
    relation_bound = relation_fanout_per_owner or fanout_per_owner
    if relation_bound > fanout_per_owner:
        raise ValueError(
            "relation_fanout_per_owner must not exceed fanout_per_owner"
        )

    triples = _edge_triples(edges)
    source_counts: Counter[str] = Counter()
    key_counts: Counter[tuple[str, str]] = Counter()
    by_source: dict[str, Counter[str]] = {}
    for source, relation, _ in triples:
        source_counts[source] += 1
        key_counts[(source, relation)] += 1
        by_source.setdefault(source, Counter())[relation] += 1

    source_excess = sum(
        max(0, count - fanout_per_owner) for count in source_counts.values()
    )
    relation_excess = sum(
        max(0, count - relation_bound) for count in key_counts.values()
    )
    # An edge can violate both bounds at once. A truncating builder applies the
    # per-relation bound first and then the source-wide bound, so retention is
    # decided per source by whichever bound binds.
    retained = 0
    for relations in by_source.values():
        kept = sum(min(count, relation_bound) for count in relations.values())
        retained += min(kept, fanout_per_owner)
    return {
        "fanout_per_owner": fanout_per_owner,
        "relation_fanout_per_owner": relation_bound,
        "edge_count": len(triples),
        "source_overflow_bucket_count": sum(
            count > fanout_per_owner for count in source_counts.values()
        ),
        "source_overflow_edge_count": source_excess,
        "source_relation_overflow_bucket_count": sum(
            count > relation_bound for count in key_counts.values()
        ),
        "source_relation_overflow_edge_count": relation_excess,
        "fits_declared_capacity": source_excess == 0 and relation_excess == 0,
        "upper_bound_retained_edge_count": retained,
        "upper_bound_retained_edge_fraction": (
            retained / len(triples) if triples else 1.0
        ),
        "retention_note": (
            "Upper bound only. It assumes a truncating builder keeps as many "
            "edges as both bounds allow; the supported preparer fails closed "
            "instead of truncating."
        ),
    }


def page_amplification(
    edges: Iterable[Any],
    *,
    page_size: int,
    pages_per_key: int = 1,
) -> dict[str, Any]:
    """Cost of storing raw edges losslessly as fixed-size relation pages.

    A ``(source, relation)`` key occupies ``ceil(degree / page_size)`` pages.
    ``pages_per_key`` is the public per-key page bound the circuit would read;
    keys needing more pages are reported as overflow rather than silently
    truncated.
    """

    if page_size < 1:
        raise ValueError("page_size must be positive")
    if pages_per_key < 1:
        raise ValueError("pages_per_key must be positive")

    triples = _edge_triples(edges)
    key_counts: Counter[tuple[str, str]] = Counter()
    for source, relation, _ in triples:
        key_counts[(source, relation)] += 1

    pages_needed = 0
    overflow_keys = 0
    overflow_edges = 0
    for count in key_counts.values():
        required = -(-count // page_size)
        pages_needed += min(required, pages_per_key)
        if required > pages_per_key:
            overflow_keys += 1
            overflow_edges += count - pages_per_key * page_size
    stored_slots = pages_needed * page_size
    return {
        "page_size": page_size,
        "pages_per_key": pages_per_key,
        "edge_count": len(triples),
        "distinct_source_relation_keys": len(key_counts),
        "pages_needed": pages_needed,
        "padded_slot_count": stored_slots,
        # >1 means padding overhead; 1.0 is a perfectly packed layout.
        "slot_amplification": (
            stored_slots / len(triples) if triples else 0.0
        ),
        "key_overflow_count": overflow_keys,
        "overflow_edge_count": overflow_edges,
        "lossless_at_this_bound": overflow_keys == 0,
        "max_pages_required_by_any_key": max(
            (-(-count // page_size) for count in key_counts.values()), default=0
        ),
    }


def retention(
    raw_edges: Iterable[Any], bounded_edges: Iterable[Any]
) -> dict[str, Any]:
    """Compare a raw edge file against an already-bounded/truncated file."""

    raw = _edge_triples(raw_edges)
    bounded = _edge_triples(bounded_edges)
    raw_set = set(raw)
    bounded_set = set(bounded)
    return {
        "raw_edge_count": len(raw),
        "bounded_edge_count": len(bounded),
        "retained_edge_fraction": (
            len(bounded) / len(raw) if raw else 1.0
        ),
        "distinct_raw_triples": len(raw_set),
        "distinct_bounded_triples": len(bounded_set),
        "bounded_triples_absent_from_raw": len(bounded_set - raw_set),
        "raw_triples_dropped": len(raw_set - bounded_set),
    }


def plan_owner_capacity(
    edges: Iterable[Any],
    *,
    candidate_page_sizes: Sequence[int] = (1, 2, 4, 8, 16, 32, 64),
    candidate_source_bounds: Sequence[int] | None = None,
    pages_per_key: int = 1,
) -> dict[str, Any]:
    """Full private planning report for one owner's raw edge file."""

    triples = _edge_triples(edges)
    profile = degree_profile(triples_as_edges(triples))
    bounds = candidate_source_bounds
    if bounds is None:
        observed = profile["max_source_degree"]
        bounds = sorted({1, 2, 4, 8, 16, 32, 64, max(1, observed)})
    return {
        "audit_scope": "supplied_file_only",
        "privacy_note": (
            "Realized degree maxima are private owner metadata. Publish them "
            "only if the deployment intentionally declares those bounds public."
        ),
        "degree_profile": profile,
        "packed_scan_bounds": [
            bound_overflow(
                triples_as_edges(triples),
                fanout_per_owner=bound,
                relation_fanout_per_owner=None,
            )
            for bound in bounds
        ],
        "relation_page_options": [
            page_amplification(
                triples_as_edges(triples),
                page_size=page_size,
                pages_per_key=pages_per_key,
            )
            for page_size in candidate_page_sizes
        ],
        "smallest_lossless_relation_page_size": _smallest_lossless_page_size(
            triples, candidate_page_sizes, pages_per_key
        ),
    }


def triples_as_edges(
    triples: Iterable[tuple[str, str, str]]
) -> list[dict[str, str]]:
    """Re-materialize validated triples as edge dicts for reuse across helpers."""

    return [
        {"source": source, "relation": relation, "target": target}
        for source, relation, target in triples
    ]


def _smallest_lossless_page_size(
    triples: Sequence[tuple[str, str, str]],
    candidate_page_sizes: Sequence[int],
    pages_per_key: int,
) -> int | None:
    edges = triples_as_edges(triples)
    for page_size in sorted(candidate_page_sizes):
        if page_amplification(
            edges, page_size=page_size, pages_per_key=pages_per_key
        )["lossless_at_this_bound"]:
            return page_size
    return None
