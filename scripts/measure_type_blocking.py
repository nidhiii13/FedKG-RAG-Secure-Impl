#!/usr/bin/env python3
"""Measure the type-blocked directory against the dense one on a real KG.

Why this exists
---------------
GORAM (PVLDB'25, ABY3) works on graphs whose edges are untyped. A knowledge
graph's edges carry relations, and that third dimension is both the reason this
project's directory is expensive (it is dense in entity x relation) and the
reason it does not have to be: a relation has a *domain*, so most
(entity, relation) pairs are not merely absent from the data, they are
**impossible under the ontology**. The ontology is public, so removing them
removes rows without removing any secret.

This script measures how much of the dense directory is type-invalid.

The type map is the load-bearing assumption
-------------------------------------------
The reduction is only leakage-free if the entity -> type map is PUBLIC input,
like the relation vocabulary already is. Deriving types from the federation's
edges would make the block widths a function of owner data and leak it.

Freebase-style relation names encode their domain syntactically
("film.actor.film" has domain "film.actor"), so ``--domain-from-name`` needs no
extra input. But entity types derived from *observed* relations are
data-dependent, so ``--types-from-data`` is a measurement convenience and its
result is an UPPER BOUND on what a real public type map would deliver: a public
map also contains entities with no observed edges of that type, which widens
every block. The script prints both readings and labels which is which.
"""

from __future__ import annotations

import argparse
import pickle
from collections import defaultdict
from pathlib import Path


def domain_of(relation: str) -> str:
    """Freebase names are `domain.type.property`, so the domain is the prefix."""

    return relation.rsplit(".", 1)[0] if "." in relation else relation


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graph", type=Path, required=True,
                        help="pickled {head: {relation: [tails]}}")
    parser.add_argument("--frontier", type=int, default=15,
                        help="hop-two addresses (global_frontier)")
    args = parser.parse_args()

    graph = pickle.loads(args.graph.read_bytes())
    relations = sorted({r for head in graph for r in graph[head]})
    entities = {h for h in graph} | {
        t for h in graph for r in graph[h] for t in graph[h][r]
    }
    entity_count, relation_count = len(entities), len(relations)

    # Entities observed carrying each domain. DATA-DERIVED -- an upper bound on
    # the reduction a public type map would give.
    by_domain: dict[str, set[str]] = defaultdict(set)
    for head in graph:
        for relation in graph[head]:
            by_domain[domain_of(relation)].add(head)

    widths = [len(by_domain[domain_of(r)]) for r in relations]
    total_rows = sum(widths)
    max_block = max(widths)
    dense_rows = entity_count * relation_count

    def cost(rows: int, per_address: int) -> int:
        # hop one reads the table; hop two folds once then reads per address.
        return rows + rows + args.frontier * per_address

    dense_cost = cost(dense_rows, entity_count)
    blocked_cost = cost(total_rows, max_block)

    print(f"entities                {entity_count:>15,}")
    print(f"relations               {relation_count:>15,}")
    print(f"distinct domains        {len(by_domain):>15,}")
    print()
    print(f"dense directory rows    {dense_rows:>15,}")
    print(f"type-blocked rows       {total_rows:>15,}"
          f"   ({dense_rows / total_rows:.0f}x fewer)")
    print(f"widest relation block   {max_block:>15,}"
          f"   ({entity_count / max_block:.0f}x narrower than E)")
    print()
    print(f"modelled products, dense-folded   {dense_cost:>15,}")
    print(f"modelled products, type-blocked   {blocked_cost:>15,}")
    print(f"                                  {dense_cost / blocked_cost:>14.0f}x")
    print()
    print("READING: the row reduction is DATA-DERIVED and therefore an UPPER "
          "BOUND. A public type map also contains entities with no observed "
          "edges of that type, which widens every block and lowers the gain.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
