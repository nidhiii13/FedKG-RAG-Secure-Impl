from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from .config import FORMAT_VERSION, PublicConfig, SCALABLE_FIELD_PRIME
from .io import read_json, write_private_json, write_private_lines
from .sharing import SERVER_COUNT, share_vector


def packing_widths(config: PublicConfig) -> tuple[int, int, int, int, int]:
    return (
        max(1, (config.entity_count - 1).bit_length()),
        max(1, max(config.relations.values()).bit_length()),
        config.evidence_bits,
        config.score_bits,
        1,
    )


def packed_edge_bits(config: PublicConfig) -> int:
    return sum(packing_widths(config))


def _require_packed_config(config: PublicConfig) -> None:
    if config.field_prime != SCALABLE_FIELD_PRIME:
        raise ValueError("packed private lookup requires field_prime=2^127-1")
    if packed_edge_bits(config) > config.field_usable_bits:
        raise ValueError(
            f"packed edge needs {packed_edge_bits(config)} bits but the field "
            f"permits {config.field_usable_bits} usable bits"
        )


def pack_edge(
    config: PublicConfig,
    target: int,
    relation: int,
    evidence: int,
    score: int,
    valid: int,
) -> int:
    _require_packed_config(config)
    values = (target, relation, evidence, score, valid)
    result = 0
    shift = 0
    for value, width in zip(values, packing_widths(config)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError("packed edge fields must be integers")
        if not 0 <= value < 1 << width:
            raise ValueError(f"packed edge value {value} does not fit in {width} bits")
        result |= value << shift
        shift += width
    return result


def unpack_edge(config: PublicConfig, value: int) -> tuple[int, int, int, int, int]:
    _require_packed_config(config)
    if not 0 <= value < 1 << packed_edge_bits(config):
        raise ValueError("non-canonical packed edge")
    result = []
    for width in packing_widths(config):
        result.append(value & ((1 << width) - 1))
        value >>= width
    return tuple(result)  # type: ignore[return-value]


def _validated_edge(
    config: PublicConfig,
    row_number: int,
    edge: dict[str, Any],
) -> tuple[int, int, int, int, int]:
    if set(edge) != {"source", "relation", "target", "evidence", "score"}:
        raise ValueError(
            f"edge {row_number} must contain exactly "
            "source/relation/target/evidence/score"
        )
    try:
        source = config.entities[edge["source"]]
        target = config.entities[edge["target"]]
        relation = config.relations[edge["relation"]]
    except (KeyError, TypeError) as exc:
        raise ValueError(f"edge {row_number} uses an unknown ontology item") from exc
    evidence = edge["evidence"]
    score = edge["score"]
    if isinstance(evidence, bool) or not isinstance(evidence, int) or evidence <= 0:
        raise ValueError(f"edge {row_number} has an invalid evidence handle")
    if isinstance(score, bool) or not isinstance(score, int) or score < 0:
        raise ValueError(f"edge {row_number} has an invalid score")
    # Enforce configured widths even when this helper is used only for a
    # capacity audit.  A report marked as fitting must also be packable.
    pack_edge(config, target, relation, evidence, score, 1)
    return source, relation, target, evidence, score


def packed_owner_capacity_report(
    config: PublicConfig,
    owner: str,
    edges: list[dict[str, Any]],
) -> dict[str, int | bool | str]:
    """Return owner-local capacity requirements for the supplied file.

    Owners can run this before sharing.  The report is deliberately not sent
    to the computation servers because exact maxima are part of the owner's
    private degree profile unless the deployment declares them public.  It
    cannot detect records discarded before this file was produced.
    """

    _require_packed_config(config)
    if owner not in config.owners:
        raise ValueError(f"unknown owner {owner!r}")
    source_counts: Counter[int] = Counter()
    relation_counts: Counter[tuple[int, int]] = Counter()
    for row_number, edge in enumerate(edges, start=1):
        source, relation, _, _, _ = _validated_edge(config, row_number, edge)
        source_counts[source] += 1
        relation_counts[(source, relation)] += 1
    required_total = max(source_counts.values(), default=0)
    required_relation = max(relation_counts.values(), default=0)
    return {
        "audit_scope": "supplied_file_only",
        "edge_count": len(edges),
        "nonempty_source_buckets": len(source_counts),
        "nonempty_source_relation_buckets": len(relation_counts),
        "required_fanout_per_owner": required_total,
        "required_relation_fanout_per_owner": required_relation,
        "configured_fanout_per_owner": config.fanout_per_owner,
        "configured_relation_fanout_per_owner": config.relation_frontier_per_owner,
        "source_overflow_bucket_count": sum(
            count > config.fanout_per_owner for count in source_counts.values()
        ),
        "source_relation_overflow_bucket_count": sum(
            count > config.relation_frontier_per_owner
            for count in relation_counts.values()
        ),
        "supplied_input_fits_declared_capacity": (
            required_total <= config.fanout_per_owner
            and required_relation <= config.relation_frontier_per_owner
        ),
    }


def packed_owner_vector(
    config: PublicConfig, owner: str, edges: list[dict[str, Any]]
) -> list[int]:
    _require_packed_config(config)
    if owner not in config.owners:
        raise ValueError(f"unknown owner {owner!r}")
    buckets: list[list[int]] = [[] for _ in range(config.entity_count)]
    relation_counts: Counter[tuple[int, int]] = Counter()
    for row_number, edge in enumerate(edges, start=1):
        source, relation, target, evidence, score = _validated_edge(
            config, row_number, edge
        )
        relation_counts[(source, relation)] += 1
        if relation_counts[(source, relation)] > config.relation_frontier_per_owner:
            raise ValueError(
                f"owner {owner!r} exceeds public bound relation_fanout_per_owner="
                f"{config.relation_frontier_per_owner} at entity slot {source}, "
                f"relation ID {relation}"
            )
        buckets[source].append(pack_edge(config, target, relation, evidence, score, 1))

    flat: list[int] = []
    for slot, bucket in enumerate(buckets):
        if len(bucket) > config.fanout_per_owner:
            raise ValueError(
                f"owner {owner!r} has {len(bucket)} edges at entity slot {slot}; "
                f"public bound is {config.fanout_per_owner}"
            )
        flat.extend(bucket)
        flat.extend([0] * (config.fanout_per_owner - len(bucket)))
    return flat


def create_packed_owner_shards(
    config: PublicConfig,
    owner: str,
    edge_path: str | Path,
    output_dir: str | Path,
) -> list[Path]:
    raw = read_json(edge_path)
    if not isinstance(raw, list):
        raise ValueError("owner edge file must be a JSON list")
    values = packed_owner_vector(config, owner, raw)
    vectors = share_vector(values, modulus=config.field_prime)
    outputs = []
    for server, shares in enumerate(vectors):
        document = {
            "version": FORMAT_VERSION,
            "kind": "packed-owner-shard",
            "config_digest": config.digest,
            "owner": owner,
            "owner_index": config.owners.index(owner),
            "server": server,
            "values": shares,
        }
        path = Path(output_dir) / (
            f"packed-owner-{config.owners.index(owner)}-to-server-{server}.json"
        )
        write_private_json(path, document)
        outputs.append(path)
    return outputs


def create_packed_query_batch_shards(
    config: PublicConfig,
    query_path: str | Path,
    output_dir: str | Path,
) -> list[Path]:
    raw = read_json(query_path)
    if not isinstance(raw, list) or not raw:
        raise ValueError("query batch must be a non-empty JSON list")
    values: list[int] = []
    for index, query in enumerate(raw):
        if not isinstance(query, dict) or set(query) != {
            "source",
            "relation_1",
            "relation_2",
        }:
            raise ValueError(
                f"query {index} must contain exactly source/relation_1/relation_2"
            )
        try:
            values.extend(
                (
                    config.entities[query["source"]],
                    config.relations[query["relation_1"]],
                    config.relations[query["relation_2"]],
                )
            )
        except (KeyError, TypeError) as exc:
            raise ValueError(f"query {index} uses an unknown ontology item") from exc

    vectors = share_vector(values, modulus=config.field_prime)
    outputs = []
    for server, shares in enumerate(vectors):
        document = {
            "version": FORMAT_VERSION,
            "kind": "packed-query-batch-shard",
            "config_digest": config.digest,
            "query_count": len(raw),
            "server": server,
            "values": shares,
        }
        path = Path(output_dir) / f"query-batch-to-server-{server}.json"
        write_private_json(path, document)
        outputs.append(path)
    return outputs


def packed_query_batch_values(
    config: PublicConfig,
    server: int,
    document: dict[str, Any],
    query_count: int,
) -> list[int]:
    if (
        document.get("version") != FORMAT_VERSION
        or document.get("kind") != "packed-query-batch-shard"
        or document.get("config_digest") != config.digest
        or document.get("query_count") != query_count
        or document.get("server") != server
    ):
        raise ValueError("packed query-batch shard metadata mismatch")
    values = document.get("values")
    if not isinstance(values, list) or len(values) != query_count * 3:
        raise ValueError("packed query-batch shard has the wrong value count")
    if any(
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value < config.field_prime
        for value in values
    ):
        raise ValueError("non-canonical packed query share")
    return values


def assemble_packed_batch_input(
    config: PublicConfig,
    server: int,
    query_values: list[int],
    owner_documents: list[dict[str, Any]],
    output_path: str | Path,
) -> Path:
    """Write query shares followed by an entity-major packed graph matrix."""
    _require_packed_config(config)
    if server not in range(SERVER_COUNT):
        raise ValueError("server must be 0, 1, or 2")
    if len(query_values) % 3:
        raise ValueError("query share vector length must be divisible by three")
    by_index: dict[int, list[int]] = {}
    expected = config.entity_count * config.fanout_per_owner
    for document in owner_documents:
        if (
            document.get("version") != FORMAT_VERSION
            or document.get("kind") != "packed-owner-shard"
            or document.get("config_digest") != config.digest
            or document.get("server") != server
        ):
            raise ValueError("packed owner shard metadata mismatch")
        index = document.get("owner_index")
        owner = document.get("owner")
        values = document.get("values")
        if (
            not isinstance(index, int)
            or index not in range(len(config.owners))
            or owner != config.owners[index]
            or index in by_index
            or not isinstance(values, list)
            or len(values) != expected
        ):
            raise ValueError("invalid packed owner shard")
        if any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value < config.field_prime
            for value in values
        ):
            raise ValueError("non-canonical packed owner share")
        by_index[index] = values
    if set(by_index) != set(range(len(config.owners))):
        raise ValueError("packed owner shard set is incomplete")

    combined = list(query_values)
    for entity in range(config.entity_count):
        start = entity * config.fanout_per_owner
        for owner_index in range(len(config.owners)):
            combined.extend(
                by_index[owner_index][start : start + config.fanout_per_owner]
            )
    destination = Path(output_path)
    write_private_lines(destination, combined)
    return destination


def assemble_packed_batch_from_paths(
    config: PublicConfig,
    server: int,
    query_count: int,
    query_shard: str | Path,
    owner_shards: list[str | Path],
    output_path: str | Path,
) -> Path:
    query_document = read_json(query_shard)
    if not isinstance(query_document, dict):
        raise ValueError("packed query-batch shard must be a JSON object")
    query_values = packed_query_batch_values(
        config, server, query_document, query_count
    )
    owner_documents = [read_json(path) for path in owner_shards]
    if any(not isinstance(document, dict) for document in owner_documents):
        raise ValueError("packed owner shards must be JSON objects")
    return assemble_packed_batch_input(
        config,
        server,
        query_values,
        owner_documents,
        output_path,
    )
