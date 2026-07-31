"""Bridge threshold-PIR candidate retrieval into aggregation and ranking.

The PIR layer is responsible only for private indexed bucket lookup. This module
keeps the next boundary explicit: encoded candidate paths are converted into
score/support shares, optionally validated with Prio3, and ranked with the local
garbled-circuit-compatible top-k implementation.

This remains a local validation bridge. A production deployment should replace
the local reconstruction in the ranking backend with distributed MPC/GC input
handling, while keeping the same candidate-share interface.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from src.aggregation.prio3_backend import Prio3BackendError, Prio3LocalBackend
from src.aggregation.prio3_candidates import (
    CandidateContribution,
    CandidateVectorConfig,
    PrioCandidateAggregator,
    SessionCandidateHandleProvider,
)
from src.aggregation.score_aggregation import CandidateShare
from src.aggregation.secret_sharing import AdditiveSharing, FixedPointEncoder
from src.ranking.garbled_circuit import LocalGarbledCircuitTopK
from src.ranking.mpspdz_candidate_topk import (
    MPSPDZCandidateTopKConfig,
    rank_candidates_with_mpspdz,
)


@dataclass(frozen=True)
class PirBridgeConfig:
    """Configuration for PIR-to-aggregation/ranking validation."""

    party_count: int
    topk: int
    candidate_capacity: int
    prio_aggregators: int
    handle_key_env: str
    query_nonce: str
    prio_cli: Path
    ranking_backend: str = "local-gc"
    mp_spdz_home: Path = Path("external/MP-SPDZ")
    mp_spdz_instance_dir: Path | None = None
    mp_spdz_keep_instance: bool = False
    mp_spdz_timeout_seconds: float = 300.0


@dataclass(frozen=True)
class PirBridgeResult:
    selected_candidate_ids: list[str]
    validation: dict[str, Any]


def aggregate_and_rank_pir_candidates(
    candidates: Sequence[dict[str, object]],
    config: PirBridgeConfig,
) -> PirBridgeResult:
    """Convert PIR-returned encoded paths into aggregate shares and top-k IDs.

    Input candidates are already encoded path records, usually produced after a
    PIR bucket lookup plus bounded path join. Each candidate is expected to have:
    ``candidate_id``, ``score`` and ``support``.
    """

    if len(candidates) > config.candidate_capacity:
        raise SystemExit(
            f"candidate count {len(candidates)} exceeds --candidate-capacity {config.candidate_capacity}"
        )

    validation: dict[str, Any] = {
        "lookup": "Lattigo threshold-PIR returns encoded bounded candidate paths",
        "score_support_shares": "candidate score/support values are additive-shared over the configured parties",
    }

    if config.ranking_backend == "mpspdz":
        ranking = rank_candidates_with_mpspdz(
            candidates,
            MPSPDZCandidateTopKConfig(
                mp_spdz_home=config.mp_spdz_home,
                party_count=config.party_count,
                topk=config.topk,
                candidate_capacity=config.candidate_capacity,
                instance_dir=config.mp_spdz_instance_dir,
                keep_instance=config.mp_spdz_keep_instance,
                timeout_seconds=config.mp_spdz_timeout_seconds,
            ),
        )
        selected_ids = ranking.selected_candidate_ids
        validation["ranking"] = {
            "backend": "MP-SPDZ semi",
            "selected_slots": ranking.selected_slots,
            "metrics": ranking.metrics,
            "production_boundary": (
                "ranking is executed inside MP-SPDZ over private score/support share inputs; "
                "only selected candidate slots are revealed"
            ),
        }
    elif config.ranking_backend == "local-gc":
        sharing = AdditiveSharing()
        encoder = FixedPointEncoder()
        candidate_shares = [
            CandidateShare(
                candidate_id=str(candidate["candidate_id"]),
                score_shares=sharing.share(encoder.encode(float(candidate["score"])), config.party_count),
                support_shares=sharing.share(int(candidate["support"]), config.party_count),
            )
            for candidate in candidates
        ]
        selected_ids = list(
            LocalGarbledCircuitTopK(party_count=config.party_count).rank(candidate_shares, config.topk)
        )
        validation["ranking"] = "local GC-compatible top-k over candidate share vectors"
        validation["production_requirement"] = (
            "use --ranking-backend mpspdz or replace local validation with distributed MPC/GC"
        )
    else:
        raise ValueError(f"unsupported ranking backend: {config.ranking_backend}")

    prio_validation = _try_prio_validation(candidates, config)
    validation["prio"] = prio_validation

    return PirBridgeResult(
        selected_candidate_ids=selected_ids,
        validation=validation,
    )


def _try_prio_validation(
    candidates: Sequence[dict[str, object]],
    config: PirBridgeConfig,
) -> dict[str, object] | str:
    handle_key = os.environ.get(config.handle_key_env)
    if not handle_key:
        return "skipped; set FEDKG_PRIO_HANDLE_KEY to validate Prio aggregation"
    if not config.prio_cli.exists():
        return f"skipped; Prio CLI not found at {config.prio_cli}"
    if not candidates:
        return "skipped; no candidates to validate"

    contributions = [
        CandidateContribution(
            party_id="threshold_pir_candidate_set",
            candidate_id=str(candidate["candidate_id"]),
            score=float(candidate["score"]),
            support=int(candidate["support"]),
        )
        for candidate in candidates
    ]
    try:
        aggregation = PrioCandidateAggregator(
            Prio3LocalBackend.from_executable(config.prio_cli),
            CandidateVectorConfig(
                aggregator_count=config.prio_aggregators,
                capacity=config.candidate_capacity,
            ),
            SessionCandidateHandleProvider(
                handle_key.encode("utf-8"),
                config.query_nonce.encode("utf-8"),
            ),
        ).aggregate(["threshold_pir_candidate_set"], contributions)
    except Prio3BackendError as exc:
        return {"error": str(exc)}

    return {
        "aggregator_count": aggregation.aggregator_count,
        "party_count": aggregation.party_count,
        "aggregate_candidate_count": len(aggregation.candidates),
        "mode": "local Prio3 validation over padded candidate vectors",
    }
