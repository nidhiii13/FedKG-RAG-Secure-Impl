#!/usr/bin/env python3
"""Rebuild the documented matched 160k relation-paged benchmark fixture.

The construction is deliberately deterministic and matches the public shape
and oracle result recorded by the existing linear relation-paged and wide KG
ORAM reports: 100,000 entities, 160,000 degree-one ``(source, relation)``
keys, three round-robin owners, and the path with evidence handles 1 and
100,002.  It writes only clear benchmark inputs; owner sharing happens in the
separate dual-ORAM preparer.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Iterator, TextIO


ENTITY_COUNT = 100_000
EDGE_COUNT = 160_000
OWNER_COUNT = 3
HE_PRIME = 170_141_183_460_469_231_731_687_303_715_885_907_969


def edge_at(index: int) -> dict[str, object]:
    """Return the unique degree-one edge at zero-based global ordinal index."""

    if not 0 <= index < EDGE_COUNT:
        raise ValueError("edge index outside the fixed fixture")
    relation_index, source_index = divmod(index, ENTITY_COUNT)
    source = source_index + 1
    target = source % ENTITY_COUNT + 1
    return {
        "source": f"e{source}",
        "relation": f"r{relation_index + 1}",
        "target": f"e{target}",
        "evidence": index + 1,
        "score": 2,
    }


def atomic_text(path: Path) -> tuple[TextIO, str]:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    os.chmod(temporary, 0o600)
    return os.fdopen(descriptor, "w", encoding="utf-8"), temporary


def write_json_atomic(path: Path, value: object) -> None:
    stream, temporary = atomic_text(path)
    try:
        with stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def owner_edges(owner: int) -> Iterator[dict[str, object]]:
    for index in range(owner, EDGE_COUNT, OWNER_COUNT):
        yield edge_at(index)


def write_owner(path: Path, owner: int) -> int:
    stream, temporary = atomic_text(path)
    count = 0
    try:
        with stream:
            stream.write("[\n")
            first = True
            for edge in owner_edges(owner):
                if not first:
                    stream.write(",\n")
                stream.write("  ")
                json.dump(edge, stream, separators=(",", ":"))
                first = False
                count += 1
            stream.write("\n]\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return count


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def build(output: Path) -> dict[str, object]:
    output = output.resolve()
    expected_files = [
        output / "config.json",
        output / "queries.json",
        *(output / f"owner_{owner}.json" for owner in range(OWNER_COUNT)),
        output / "fixture_manifest.json",
    ]
    if any(path.exists() for path in expected_files):
        raise FileExistsError("refusing to overwrite an existing 160k fixture")

    config = {
        "owners": [f"owner_{owner}" for owner in range(OWNER_COUNT)],
        "entities": {f"e{entity}": entity for entity in range(1, ENTITY_COUNT + 1)},
        "relations": {"r1": 1, "r2": 2, "r3": 3},
        "fanout_per_owner": 2,
        "top_k": 4,
        "field_prime": HE_PRIME,
        "relation_page_layout": {
            "page_size": 2,
            "pages_per_key": 1,
            "page_budget": 53_335,
            "frontier_per_owner": 1,
            "global_frontier": 1,
        },
    }
    query = [{"source": "e1", "relation_1": "r1", "relation_2": "r2"}]
    write_json_atomic(output / "config.json", config)
    write_json_atomic(output / "queries.json", query)
    counts = [
        write_owner(output / f"owner_{owner}.json", owner)
        for owner in range(OWNER_COUNT)
    ]
    if counts != [53_334, 53_333, 53_333]:
        raise AssertionError(f"unexpected owner counts: {counts}")

    files = [output / "config.json", output / "queries.json"] + [
        output / f"owner_{owner}.json" for owner in range(OWNER_COUNT)
    ]
    manifest: dict[str, object] = {
        "kind": "matched-relation-paged-160k-degree-one-fixture",
        "entities": ENTITY_COUNT,
        "relations": 3,
        "edges": EDGE_COUNT,
        "owners": OWNER_COUNT,
        "owner_edge_counts": counts,
        "maximum_owner_key_degree": 1,
        "maximum_federation_key_degree": 1,
        "query": query[0],
        "expected_rank_zero": {
            "valid": 1,
            "left_evidence": 1,
            "right_evidence": 100_002,
            "score": 4,
        },
        "sha256": {path.name: sha256(path) for path in files},
    }
    write_json_atomic(output / "fixture_manifest.json", manifest)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(build(args.output_dir), indent=2))


if __name__ == "__main__":
    main()
