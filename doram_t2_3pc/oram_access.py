"""Preparation contract for the experimental read-only recursive ORAM.

The owner constructs the ORAM stack in plaintext because it already knows its
records, then distributes a perfect 3-out-of-3 additive sharing of the finished
state.  The client shares only logical addresses.  Concatenating the matching
owner and client shards yields one MP-SPDZ input stream per computation server;
the preparation roles never have to exchange plaintext values.

This module deliberately contains no claim that the ORAM is integrated with the
KG backend.  It is the role-separated input boundary for the standalone access
circuit in :mod:`doram_t2_3pc.oram_access_program`.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Iterator, Sequence

from .oram_layout import OwnerOramStack
from .sharing import SERVER_COUNT, reconstruct, share_vector


ORAM_SHARE_LINE = re.compile(
    r"ORAM_ACCESS_SHARE\s+(\d+)\s+(\d+)\s+([0-2])\s+(-?\d+)"
)


@dataclass(frozen=True)
class OramLevelShape:
    size: int
    bucket_size: int
    depth: int
    slots: int
    field_count: int


@dataclass(frozen=True)
class OramAccessShape:
    levels: tuple[OramLevelShape, ...]
    base_entries: int
    chi: int
    value_width: int
    max_accesses: int

    @classmethod
    def from_stack(
        cls, stack: OwnerOramStack, *, max_accesses: int
    ) -> "OramAccessShape":
        if max_accesses < 1:
            raise ValueError("max_accesses must be positive")
        if stack.chi < 2 or stack.chi & (stack.chi - 1):
            raise ValueError("the MPC access circuit requires power-of-two chi")
        if len(stack.base) < 1:
            raise ValueError("the recursive position-map base must not be empty")
        return cls(
            levels=tuple(
                OramLevelShape(
                    size=tree.size,
                    bucket_size=tree.bucket_size,
                    depth=tree.depth,
                    slots=tree.slots,
                    field_count=tree.field_count,
                )
                for tree in stack.levels
            ),
            base_entries=len(stack.base),
            chi=stack.chi,
            value_width=stack.levels[0].field_count - 3,
            max_accesses=max_accesses,
        )

    @property
    def owner_values(self) -> int:
        return sum(level.slots * level.field_count for level in self.levels) + self.base_entries

    @property
    def client_values(self) -> int:
        return self.max_accesses

    @property
    def total_values_per_server(self) -> int:
        return self.owner_values + self.client_values


@dataclass(frozen=True)
class OramInputShards:
    shape: OramAccessShape
    server_values: tuple[list[int], list[int], list[int]]


def flatten_owner_stack(stack: OwnerOramStack) -> list[int]:
    """Flatten in the exact field-major order consumed by the MPC circuit."""

    values: list[int] = []
    for tree in stack.levels:
        values.extend(tree.flat_values())
    values.extend(stack.base)
    return values


def iter_flatten_owner_stack(stack: OwnerOramStack) -> Iterator[int]:
    """Streaming equivalent of :func:`flatten_owner_stack` for large states."""

    for tree in stack.levels:
        for field in tree.fields:
            yield from field
    yield from stack.base


def share_owner_stack(
    stack: OwnerOramStack, *, max_accesses: int, modulus: int
) -> OramInputShards:
    shape = OramAccessShape.from_stack(stack, max_accesses=max_accesses)
    pieces = share_vector(flatten_owner_stack(stack), modulus=modulus)
    return OramInputShards(shape, pieces)


def share_access_addresses(
    addresses: Sequence[int], *, shape: OramAccessShape, modulus: int
) -> tuple[list[int], list[int], list[int]]:
    if len(addresses) != shape.max_accesses:
        raise ValueError(
            f"expected exactly {shape.max_accesses} addresses; got {len(addresses)}"
        )
    if any(isinstance(address, bool) or not isinstance(address, int) for address in addresses):
        raise TypeError("ORAM addresses must be integers")
    if any(not 0 <= address < shape.levels[0].size for address in addresses):
        raise ValueError("ORAM address is outside the logical data domain")
    return share_vector(addresses, modulus=modulus)


def assemble_oram_inputs(
    owner: OramInputShards,
    client: tuple[list[int], list[int], list[int]],
) -> OramInputShards:
    if len(client) != SERVER_COUNT:
        raise ValueError(f"expected exactly {SERVER_COUNT} client shards")
    for shard in client:
        if len(shard) != owner.shape.client_values:
            raise ValueError("client shard length does not match the ORAM access shape")
    combined = tuple(
        list(owner.server_values[server]) + list(client[server])
        for server in range(SERVER_COUNT)
    )
    return OramInputShards(owner.shape, combined)  # type: ignore[arg-type]


def decode_oram_access_logs(
    logs: Sequence[str | Path], *, shape: OramAccessShape, modulus: int
) -> list[dict[str, object]]:
    """Reconstruct only at the external client from three private server logs."""

    if len(logs) != SERVER_COUNT:
        raise ValueError("the client requires exactly three ORAM output logs")
    shares: dict[tuple[int, int], dict[int, int]] = {}
    for expected_server, log in enumerate(logs):
        for match in ORAM_SHARE_LINE.finditer(Path(log).read_text(encoding="utf-8")):
            access, field, claimed_server, value = map(int, match.groups())
            if claimed_server != expected_server:
                raise ValueError("ORAM output log contains another server's share")
            if access not in range(shape.max_accesses):
                raise ValueError("ORAM output contains an invalid access number")
            if field not in range(shape.value_width + 1):
                raise ValueError("ORAM output contains an invalid field number")
            bucket = shares.setdefault((access, field), {})
            if expected_server in bucket:
                raise ValueError("duplicate ORAM output share")
            bucket[expected_server] = value % modulus

    expected = {
        (access, field)
        for access in range(shape.max_accesses)
        for field in range(shape.value_width + 1)
    }
    if set(shares) != expected or any(
        set(pieces) != set(range(SERVER_COUNT)) for pieces in shares.values()
    ):
        raise ValueError("missing or unexpected ORAM output shares")

    results: list[dict[str, object]] = []
    for access in range(shape.max_accesses):
        found = reconstruct(
            (shares[(access, 0)][server] for server in range(SERVER_COUNT)),
            modulus=modulus,
        )
        if found not in (0, 1):
            raise ValueError("ORAM returned a non-boolean found flag")
        values = [
            reconstruct(
                (shares[(access, field)][server] for server in range(SERVER_COUNT)),
                modulus=modulus,
            )
            for field in range(1, shape.value_width + 1)
        ]
        if not found and any(values):
            raise ValueError("missing ORAM record has a non-zero payload")
        results.append({"found": found, "values": values})
    return results
