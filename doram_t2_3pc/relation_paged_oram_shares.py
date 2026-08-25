"""Role-separated inputs for the dual-stack relation-paged ORAM layer."""

from __future__ import annotations

import os
import re
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from .oram_access import OramAccessShape
from .oram_layout import OwnerOramStack
from .relation_paged_oram import OwnerRelationPagedOram
from .relation_paged_oram_epoch import (
    RelationPagedOramEpochAuthorization,
    dual_access_counts,
)
from .relation_pages import RelationPageConfig
from .sharing import SERVER_COUNT, share_vector


EPOCH_ID = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class RelationPagedOramShape:
    directory: OramAccessShape
    pages: OramAccessShape

    @property
    def owner_values(self) -> int:
        return self.directory.owner_values + self.pages.owner_values


@dataclass(frozen=True)
class RelationPagedOramOwnerShard:
    epoch_id: str
    config_digest: str
    owner: str
    owner_index: int
    server: int
    shape: RelationPagedOramShape
    values: list[int]


@dataclass(frozen=True)
class RelationPagedOramQueryShard:
    epoch_id: str
    config_digest: str
    query_count: int
    server: int
    values: list[int]


def _validate_epoch(epoch_id: str) -> None:
    if not EPOCH_ID.fullmatch(epoch_id):
        raise ValueError("epoch_id must be exactly 64 lowercase hexadecimal characters")


def shape_for_owner(
    config: RelationPageConfig,
    owner: OwnerRelationPagedOram,
    *,
    query_count: int,
) -> RelationPagedOramShape:
    directory_accesses, page_accesses = dual_access_counts(config, query_count)
    return RelationPagedOramShape(
        directory=OramAccessShape.from_stack(
            owner.directory_stack, max_accesses=directory_accesses
        ),
        pages=OramAccessShape.from_stack(
            owner.page_stack, max_accesses=page_accesses
        ),
    )


def common_shape(
    config: RelationPageConfig,
    owners: Sequence[OwnerRelationPagedOram],
    *,
    query_count: int,
) -> RelationPagedOramShape:
    if [owner.owner for owner in owners] != list(config.base.owners):
        raise ValueError("owners must appear exactly in public federation order")
    shapes = [
        shape_for_owner(config, owner, query_count=query_count) for owner in owners
    ]
    if not shapes or any(shape != shapes[0] for shape in shapes[1:]):
        raise ValueError("every owner must have the same public dual-ORAM shape")
    return shapes[0]


def iter_flatten_stack_physical(stack: OwnerOramStack) -> Iterator[int]:
    """Yield physical-record-major values consumed efficiently by MP-SPDZ."""

    for tree in stack.levels:
        for physical in range(tree.slots):
            for field in tree.fields:
                yield field[physical]
    yield from stack.base


def iter_flatten_relation_paged_oram(
    owner: OwnerRelationPagedOram,
) -> Iterator[int]:
    """Directory stack first, followed by the page stack."""

    yield from iter_flatten_stack_physical(owner.directory_stack)
    yield from iter_flatten_stack_physical(owner.page_stack)


def flatten_relation_paged_oram(owner: OwnerRelationPagedOram) -> list[int]:
    return list(iter_flatten_relation_paged_oram(owner))


def create_owner_shards(
    config: RelationPageConfig,
    owner: OwnerRelationPagedOram,
    owner_index: int,
    *,
    query_count: int,
    epoch_id: str,
) -> tuple[
    RelationPagedOramOwnerShard,
    RelationPagedOramOwnerShard,
    RelationPagedOramOwnerShard,
]:
    _validate_epoch(epoch_id)
    if owner_index not in range(len(config.base.owners)):
        raise ValueError("owner_index is outside the federation")
    if owner.owner != config.base.owners[owner_index]:
        raise ValueError("owner identity does not match owner_index")
    shape = shape_for_owner(config, owner, query_count=query_count)
    pieces = share_vector(
        flatten_relation_paged_oram(owner), modulus=config.base.field_prime
    )
    return tuple(
        RelationPagedOramOwnerShard(
            epoch_id,
            config.digest,
            owner.owner,
            owner_index,
            server,
            shape,
            pieces[server],
        )
        for server in range(SERVER_COUNT)
    )  # type: ignore[return-value]


def create_query_shards(
    config: RelationPageConfig,
    queries: Sequence[dict[str, str]],
    *,
    epoch_id: str,
) -> tuple[
    RelationPagedOramQueryShard,
    RelationPagedOramQueryShard,
    RelationPagedOramQueryShard,
]:
    _validate_epoch(epoch_id)
    if not queries:
        raise ValueError("query batch must not be empty")
    values: list[int] = []
    for query in queries:
        if set(query) != {"source", "relation_1", "relation_2"}:
            raise ValueError("each query requires source, relation_1, and relation_2")
        try:
            values.extend((
                config.base.entities[query["source"]],
                config.base.relations[query["relation_1"]],
                config.base.relations[query["relation_2"]],
            ))
        except KeyError as exc:
            raise ValueError(
                f"query contains an unknown ontology item: {exc.args[0]}"
            ) from exc
    pieces = share_vector(values, modulus=config.base.field_prime)
    return tuple(
        RelationPagedOramQueryShard(
            epoch_id, config.digest, len(queries), server, pieces[server]
        )
        for server in range(SERVER_COUNT)
    )  # type: ignore[return-value]


def _random_field_values(
    modulus: int, *, block_values: int = 32768
) -> Iterator[int]:
    if modulus < 2:
        raise ValueError("modulus must be at least two")
    bits = modulus.bit_length()
    byte_width = (bits + 7) // 8
    mask = (1 << bits) - 1
    while True:
        block = os.urandom(byte_width * block_values)
        for offset in range(0, len(block), byte_width):
            candidate = (
                int.from_bytes(block[offset:offset + byte_width], "little") & mask
            )
            if candidate < modulus:
                yield candidate


def write_owner_shards(
    owner: OwnerRelationPagedOram,
    destinations: Sequence[str | Path],
    *,
    modulus: int,
) -> None:
    """Stream 3-of-3 shares of both stacks to atomic owner-local files."""

    if len(destinations) != SERVER_COUNT:
        raise ValueError("exactly three owner-shard destinations are required")
    paths = [Path(path) for path in destinations]
    temporary: list[str] = []
    streams = []
    try:
        for path in paths:
            path.parent.mkdir(parents=True, exist_ok=True)
            descriptor, name = tempfile.mkstemp(
                prefix=f".{path.name}.", dir=path.parent
            )
            os.chmod(name, 0o600)
            temporary.append(name)
            streams.append(os.fdopen(descriptor, "w", encoding="utf-8"))
        chunks: list[list[str]] = [[], [], []]
        masks = _random_field_values(modulus)
        for value in iter_flatten_relation_paged_oram(owner):
            first, second = next(masks), next(masks)
            pieces = (first, second, (value - first - second) % modulus)
            for server in range(SERVER_COUNT):
                chunks[server].append(str(pieces[server]))
                if len(chunks[server]) == 4096:
                    streams[server].write("\n".join(chunks[server]) + "\n")
                    chunks[server].clear()
        for server in range(SERVER_COUNT):
            if chunks[server]:
                streams[server].write("\n".join(chunks[server]) + "\n")
            streams[server].flush()
            os.fsync(streams[server].fileno())
            streams[server].close()
        streams.clear()
        for name, path in zip(temporary, paths):
            os.replace(name, path)
        temporary.clear()
    finally:
        for stream in streams:
            stream.close()
        for name in temporary:
            try:
                os.unlink(name)
            except FileNotFoundError:
                pass


def assemble_server_input(
    config: RelationPageConfig,
    server: int,
    owner_shards: Sequence[RelationPagedOramOwnerShard],
    query_shard: RelationPagedOramQueryShard,
    authorization: RelationPagedOramEpochAuthorization,
) -> tuple[RelationPagedOramShape, list[int]]:
    """Validate metadata before concatenating shares; never reconstruct data."""

    if server not in range(SERVER_COUNT) or query_shard.server != server:
        raise ValueError("query shard is assigned to another server")
    ordered = sorted(owner_shards, key=lambda shard: shard.owner_index)
    if [shard.owner for shard in ordered] != list(config.base.owners):
        raise ValueError(
            "owner shards are missing, duplicated, or out of federation order"
        )
    metadata = {
        (shard.epoch_id, shard.config_digest, shard.server, shard.shape)
        for shard in ordered
    }
    if len(metadata) != 1:
        raise ValueError(
            "owner shards disagree on epoch, config, server, or dual-ORAM shape"
        )
    epoch_id, digest, shard_server, shape = next(iter(metadata))
    if shard_server != server or digest != config.digest:
        raise ValueError("owner shard metadata does not match this server/config")
    if (query_shard.epoch_id, query_shard.config_digest) != (epoch_id, digest):
        raise ValueError("query and owner shards belong to different epochs/configs")
    authorization.validate(
        config, epoch_id=epoch_id, query_count=query_shard.query_count
    )
    if any(len(shard.values) != shape.owner_values for shard in ordered):
        raise ValueError("owner shard has an invalid private-input length")
    if len(query_shard.values) != query_shard.query_count * 3:
        raise ValueError("query shard has an invalid private-input length")
    values = [value for shard in ordered for value in shard.values]
    values.extend(query_shard.values)
    return shape, values
