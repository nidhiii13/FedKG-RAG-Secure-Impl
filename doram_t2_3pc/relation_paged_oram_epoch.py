"""Fail-closed epochs for the dual-stack relation-paged ORAM backend."""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from .relation_pages import RelationPageConfig


EPOCH_ID = re.compile(r"[0-9a-f]{64}")


def dual_access_counts(
    config: RelationPageConfig, query_count: int
) -> tuple[int, int]:
    """Return fixed directory/page accesses issued by each owner stack."""

    if query_count < 1:
        raise ValueError("query_count must be positive")
    logical_reads = query_count * (
        1 + config.pages.frontier_slots(len(config.base.owners))
    )
    return logical_reads, logical_reads * config.pages.pages_per_key


@dataclass(frozen=True)
class RelationPagedOramEpochAuthorization:
    epoch_id: str
    config_digest: str
    query_count: int
    directory_accesses_per_owner: int
    page_accesses_per_owner: int
    global_frontier: int
    bound_violations: int

    @classmethod
    def accepted(
        cls,
        config: RelationPageConfig,
        *,
        epoch_id: str,
        query_count: int,
        bound_violations: int,
    ) -> "RelationPagedOramEpochAuthorization":
        if not EPOCH_ID.fullmatch(epoch_id):
            raise ValueError(
                "epoch_id must be exactly 64 lowercase hexadecimal characters"
            )
        if config.pages.global_frontier is None:
            raise ValueError(
                "relation-paged ORAM requires a federation-wide frontier bound"
            )
        if bound_violations != 0:
            raise ValueError("cannot authorize an epoch with frontier-bound violations")
        directory, pages = dual_access_counts(config, query_count)
        return cls(
            epoch_id=epoch_id,
            config_digest=config.digest,
            query_count=query_count,
            directory_accesses_per_owner=directory,
            page_accesses_per_owner=pages,
            global_frontier=config.pages.global_frontier,
            bound_violations=0,
        )

    def validate(
        self,
        config: RelationPageConfig,
        *,
        epoch_id: str,
        query_count: int,
    ) -> None:
        expected = self.accepted(
            config,
            epoch_id=epoch_id,
            query_count=query_count,
            bound_violations=0,
        )
        if self != expected:
            raise ValueError(
                "dual-ORAM epoch authorization does not match the config, "
                "query batch, or fixed access schedules"
            )


def consume_relation_paged_oram_epoch_once(
    root: str | Path,
    server: int,
    authorization: RelationPagedOramEpochAuthorization,
) -> Path:
    """Atomically reject replay of either stack under the same epoch."""

    if server not in range(3):
        raise ValueError("server must be 0, 1, or 2")
    directory = Path(root)
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    marker = directory / f"server-{server}-{authorization.epoch_id}.dual-oram.json"
    try:
        descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise ValueError(
            "dual-ORAM epoch has already been consumed on this server; both "
            "directory and page stacks require fresh randomized shares"
        ) from exc
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(asdict(authorization), stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        marker.unlink(missing_ok=True)
        raise
    return marker
