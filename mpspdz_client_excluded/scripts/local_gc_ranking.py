"""Local garbled-circuit ranking hook for MP-SPDZ ORAM outputs.

This module intentionally ranks only paths that have already been selected by
the MP-SPDZ private top-k circuit. It is useful for exercising the same
`LocalGarbledCircuitTopK` backend used by the FSS/private-frontier pipeline, but
it is not a distributed GC replacement for hidden ORAM candidate ranking.
"""

from __future__ import annotations

from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.aggregation.score_aggregation import MatchScoreShareBuilder, candidate_id_for_match
from src.common.types import MatchResult
from src.ranking.garbled_circuit import LocalGarbledCircuitTopK


def rerank_selected_paths_with_local_gc(
    paths: list[dict],
    *,
    party_count: int,
    k: int,
) -> tuple[list[dict], dict]:
    """Rank already revealed path records with the local GC prototype."""

    if not paths:
        return [], {
            "enabled": True,
            "backend": "LocalGarbledCircuitTopK",
            "scope": "already-selected-mp-spdz-output",
            "ranked_candidate_ids": [],
        }
    matches = [
        MatchResult(
            score=float(path.get("score", 0.0)),
            edges=[tuple(edge) for edge in path["edges"]],
            reuse_nodes=False,
        )
        for path in paths
    ]
    share_count = max(2, party_count)
    share_builder = MatchScoreShareBuilder(share_count=share_count)
    shares = share_builder.share_matches(matches)
    ranker = LocalGarbledCircuitTopK(party_count=share_count)
    selected_ids = list(ranker.rank(shares, min(k, len(shares))))
    by_id = {
        candidate_id_for_match(match): path
        for match, path in zip(matches, paths)
    }
    ranked_paths = []
    for rank, candidate_id in enumerate(selected_ids):
        path = dict(by_id[candidate_id])
        path["rank"] = rank
        path["local_gc_candidate_id"] = candidate_id
        ranked_paths.append(path)
    return ranked_paths, {
        "enabled": True,
        "backend": "LocalGarbledCircuitTopK",
        "scope": "already-selected-mp-spdz-output",
        "party_count": share_count,
        "ranked_candidate_ids": selected_ids,
        "security_note": (
            "This local GC hook reranks only paths already selected/revealed by MP-SPDZ. "
            "It does not replace hidden-candidate MPC top-k with distributed GC."
        ),
    }
