"""Fail-closed epoch authorization for the bounded read-only ORAM backend."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path

from .kg_oram_program import access_count_per_owner
from .relation_pages import RelationPageConfig


@dataclass(frozen=True)
class KgOramEpochAuthorization:
    epoch_id: str
    config_digest: str
    query_count: int
    accesses_per_owner: int
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
    ) -> "KgOramEpochAuthorization":
        if config.pages.global_frontier is None:
            raise ValueError("KG ORAM deployment requires a federation-wide frontier bound")
        if bound_violations != 0:
            raise ValueError("cannot authorize an epoch with frontier-bound violations")
        if query_count < 1:
            raise ValueError("query_count must be positive")
        return cls(
            epoch_id=epoch_id,
            config_digest=config.digest,
            query_count=query_count,
            accesses_per_owner=access_count_per_owner(config, query_count),
            global_frontier=config.pages.global_frontier,
            bound_violations=0,
        )

    def validate(self, config: RelationPageConfig, *, epoch_id: str, query_count: int) -> None:
        expected = KgOramEpochAuthorization.accepted(
            config, epoch_id=epoch_id, query_count=query_count, bound_violations=0
        )
        if self != expected:
            raise ValueError("epoch authorization does not match config, query batch, or access schedule")


def consume_epoch_once(root: str | Path, server: int, authorization: KgOramEpochAuthorization) -> Path:
    """Atomically mark an epoch used on one server; replay fails before MPC."""

    if server not in range(3):
        raise ValueError("server must be 0, 1, or 2")
    directory = Path(root)
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    marker = directory / f"server-{server}-{authorization.epoch_id}.consumed.json"
    try:
        descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise ValueError(
            "ORAM epoch has already been consumed on this server; tree shares "
            "must be freshly randomized before another run"
        ) from exc
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(asdict(authorization), stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            marker.unlink()
        except FileNotFoundError:
            pass
        raise
    return marker

