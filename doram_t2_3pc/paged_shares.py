"""Secret sharing and server-input assembly for the relation-paged layout.

The trust model is identical to the packed scan backend: owners and the client
are external roles that produce 3-of-3 additive shares locally, each server
receives only its own share, and nothing here needs a dealer, a setup
authority, or any cross-owner interaction.

Two tables are shared per deployment:

``directory``
    ``directory_rows`` rows of ``owner_count`` descriptors; row
    ``source * relation_count + (relation - 1)``, column ``owner_index``.
``pages``
    ``owner_count * pool_rows`` rows of ``page_size`` packed edges; owner
    ``o``'s page ``p`` is at row ``o * pool_rows + p``.

Both are padded to their public bounds before sharing, so the shared shape
reveals only the declared configuration, never a realized degree or page count.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import FORMAT_VERSION
from .io import read_json, write_private_json, write_private_lines
from .relation_pages import (
    RelationPageConfig,
    build_owner_page_layout,
    owner_occupancy_vector,
)
from .sharing import SERVER_COUNT, share_vector


def owner_flat_vector(
    config: RelationPageConfig, owner: str, edges: list[dict[str, Any]]
) -> tuple[list[int], list[int]]:
    """Return this owner's (directory, page-pool) vectors in program order."""

    layout = build_owner_page_layout(config, owner, edges)
    params = config.pages
    if len(layout.directory) != config.directory_rows:
        raise AssertionError("directory height does not match the configuration")
    directory_vector: list[int] = list(layout.directory)
    if params.uses_compact_directory:
        # Re-index the dense layout into the compact table. The dense row index
        # IS the key, so no extra information is needed and the two layouts stay
        # provably consistent: whatever the dense builder placed at row r is what
        # the compact table stores under tag r + 1.
        from .compact_directory import build_owner_table

        directory_vector = build_owner_table(
            {
                row + 1: descriptor
                for row, descriptor in enumerate(layout.directory)
                if descriptor
            },
            owner_index=config.base.owners.index(owner),
            buckets=params.directory_buckets,
            slots=params.bucket_slots,
            owner_count=len(config.base.owners),
            descriptor_bits=params.descriptor_bits,
        )
    if len(layout.pages) != params.pool_rows:
        raise AssertionError("page pool height does not match the configuration")
    flat_pages: list[int] = []
    for page in layout.pages:
        if len(page) != params.page_size:
            raise AssertionError("page width does not match the configuration")
        flat_pages.extend(page)
    return directory_vector, flat_pages


def create_paged_owner_shards(
    config: RelationPageConfig,
    owner: str,
    edge_path: str | Path,
    output_dir: str | Path,
) -> list[Path]:
    raw = read_json(edge_path)
    if not isinstance(raw, list):
        raise ValueError("owner edge file must be a JSON list")
    directory, pages = owner_flat_vector(config, owner, raw)
    directory_shares = share_vector(directory, modulus=config.base.field_prime)
    page_shares = share_vector(pages, modulus=config.base.field_prime)
    # Only needed when the layout declares a federation-wide bound, and only
    # consumed by the one-time bound check, never by the retrieval circuit.
    occupancy_shares = None
    if config.pages.uses_global_frontier:
        occupancy_shares = share_vector(
            owner_occupancy_vector(config, owner, raw),
            modulus=config.base.field_prime,
        )
    owner_index = config.base.owners.index(owner)
    outputs: list[Path] = []
    for server in range(SERVER_COUNT):
        document = {
            "version": FORMAT_VERSION,
            "kind": "paged-owner-shard",
            "layout_digest": config.digest,
            "owner": owner,
            "owner_index": owner_index,
            "server": server,
            "directory": directory_shares[server],
            "pages": page_shares[server],
        }
        if occupancy_shares is not None:
            document["occupancy"] = occupancy_shares[server]
        path = Path(output_dir) / (
            f"paged-owner-{owner_index}-to-server-{server}.json"
        )
        write_private_json(path, document)
        outputs.append(path)
    return outputs


def _validated_owner_document(
    config: RelationPageConfig, server: int, document: Any
) -> tuple[int, list[int], list[int]]:
    if not isinstance(document, dict):
        raise ValueError("paged owner shard must be a JSON object")
    if (
        document.get("version") != FORMAT_VERSION
        or document.get("kind") != "paged-owner-shard"
        or document.get("layout_digest") != config.digest
        or document.get("server") != server
    ):
        raise ValueError("paged owner shard metadata mismatch")
    index = document.get("owner_index")
    owner = document.get("owner")
    if (
        not isinstance(index, int)
        or isinstance(index, bool)
        or index not in range(len(config.base.owners))
        or owner != config.base.owners[index]
    ):
        raise ValueError("paged owner shard identifies an unknown owner")
    directory = document.get("directory")
    pages = document.get("pages")
    expected_pages = config.pages.pool_rows * config.pages.page_size
    params = config.pages
    expected_directory = (
        params.directory_buckets * len(config.base.owners) * params.bucket_slots
        if params.uses_compact_directory
        else config.directory_rows
    )
    if (
        not isinstance(directory, list)
        or len(directory) != expected_directory
        or not isinstance(pages, list)
        or len(pages) != expected_pages
    ):
        raise ValueError("paged owner shard has the wrong value count")
    prime = config.base.field_prime
    for values in (directory, pages):
        if any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value < prime
            for value in values
        ):
            raise ValueError("non-canonical paged owner share")
    return index, directory, pages


def assemble_paged_batch_input(
    config: RelationPageConfig,
    server: int,
    query_values: list[int],
    owner_documents: list[Any],
    output_path: str | Path,
) -> Path:
    """Write one server's private input in exact program consumption order.

    Order is queries, then the owner-major directory matrix, then the page
    pool. It must match ``page_program.render_program`` exactly; the runner
    re-checks the resulting line count before launching MP-SPDZ.
    """

    if server not in range(SERVER_COUNT):
        raise ValueError("server must be 0, 1, or 2")
    if len(query_values) % 3:
        raise ValueError("query share vector length must be divisible by three")

    by_index: dict[int, tuple[list[int], list[int]]] = {}
    for document in owner_documents:
        index, directory, pages = _validated_owner_document(
            config, server, document
        )
        if index in by_index:
            raise ValueError("duplicate paged owner shard")
        by_index[index] = (directory, pages)
    if set(by_index) != set(range(len(config.base.owners))):
        raise ValueError("paged owner shard set is incomplete")

    combined = list(query_values)
    # Directory: row-major over (source, relation), then one element per packed
    # column. Several owners' descriptors share an element in disjoint bit
    # ranges, so a column is the modular SUM of those owners' shifted shares --
    # valid because additive sharing is linear, and it means each owner still
    # produced its shard alone with no knowledge of the others.
    prime = config.base.field_prime
    owner_count = len(config.base.owners)
    if config.pages.uses_compact_directory:
        # Compact: each owner already occupies its own columns and is zero
        # elsewhere, so the table is the plain modular sum with no shifting --
        # the tag/descriptor packing happens inside a slot, not across owners.
        width = len(by_index[0][0])
        for position in range(width):
            total = 0
            for owner_index in range(owner_count):
                total = (total + by_index[owner_index][0][position]) % prime
            combined.append(total)
    else:
        for row in range(config.directory_rows):
            columns = [0] * config.directory_columns
            for owner_index in range(owner_count):
                column, offset = config.directory_slot(owner_index)
                shifted = (by_index[owner_index][0][row] << offset) % prime
                columns[column] = (columns[column] + shifted) % prime
            combined.extend(columns)
    # Pages: owner-major so each owner's pool is a contiguous scan range.
    for owner_index in range(len(config.base.owners)):
        combined.extend(by_index[owner_index][1])

    destination = Path(output_path)
    write_private_lines(destination, combined)
    return destination


def expected_private_input_values(
    config: RelationPageConfig, query_count: int
) -> int:
    owner_count = len(config.base.owners)
    params = config.pages
    if params.uses_compact_directory:
        directory_values = (
            params.directory_buckets * owner_count * params.bucket_slots
        )
    else:
        directory_values = config.directory_rows * config.directory_columns
    return (
        query_count * 3
        + directory_values
        + owner_count * config.pages.pool_rows * config.pages.page_size
    )


def assemble_paged_batch_from_paths(
    config: RelationPageConfig,
    server: int,
    query_count: int,
    query_shard: str | Path,
    owner_shards: list[str | Path],
    output_path: str | Path,
) -> Path:
    from .packed import packed_query_batch_values

    query_document = read_json(query_shard)
    if not isinstance(query_document, dict):
        raise ValueError("query-batch shard must be a JSON object")
    # The query contract is unchanged from the packed backend, so its shard
    # format and validation are reused verbatim.
    query_values = packed_query_batch_values(
        config.base, server, query_document, query_count
    )
    documents = [read_json(path) for path in owner_shards]
    return assemble_paged_batch_input(
        config, server, query_values, documents, output_path
    )


def validate_private_input(
    config: RelationPageConfig, query_count: int, path: str | Path
) -> None:
    expected = expected_private_input_values(config, query_count)
    observed = 0
    prime = config.base.field_prime
    with Path(path).open("r", encoding="utf-8") as stream:
        for line in stream:
            observed += 1
            try:
                value = int(line)
            except ValueError as exc:
                raise ValueError(
                    "private server input contains a non-integer"
                ) from exc
            if not 0 <= value < prime:
                raise ValueError(
                    "private server input contains a non-canonical field element"
                )
    if observed != expected:
        raise ValueError(
            f"private server input has {observed} values; expected {expected}"
        )


def assemble_bound_check_input(
    config: RelationPageConfig,
    server: int,
    owner_shard_paths: list[str | Path],
    output_path: str | Path,
) -> Path:
    """Write one server's input for the one-time federation-wide bound check.

    Every owner wrote its per-key count at the same position, so the servers'
    additive sum of these shares is the federation-wide count. This function
    therefore just adds them: no owner learns another's counts, and no oblivious
    machinery is involved.
    """

    if server not in range(SERVER_COUNT):
        raise ValueError("server must be 0, 1, or 2")
    if not config.pages.uses_global_frontier:
        raise ValueError("layout does not declare global_frontier")

    prime = config.base.field_prime
    totals = [0] * config.directory_rows
    seen: set[int] = set()
    for path in owner_shard_paths:
        document = read_json(path)
        index, _, _ = _validated_owner_document(config, server, document)
        if index in seen:
            raise ValueError("duplicate paged owner shard")
        seen.add(index)
        occupancy = document.get("occupancy")
        if (
            not isinstance(occupancy, list)
            or len(occupancy) != config.directory_rows
            or any(
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 <= value < prime
                for value in occupancy
            )
        ):
            raise ValueError(
                "paged owner shard is missing a well-formed occupancy vector; "
                "re-create the shards with a layout declaring global_frontier"
            )
        for row, value in enumerate(occupancy):
            totals[row] = (totals[row] + value) % prime
    if seen != set(range(len(config.base.owners))):
        raise ValueError("paged owner shard set is incomplete")

    destination = Path(output_path)
    write_private_lines(destination, totals)
    return destination
