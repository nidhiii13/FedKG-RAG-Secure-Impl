"""MP-SPDZ ranking backend for bounded PIR candidate sets."""

from __future__ import annotations

import os
import random
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from src.aggregation.secret_sharing import FixedPointEncoder


REPO_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = REPO_ROOT / "mpspdz_client_excluded" / "programs" / "secure_candidate_share_topk.mpc.template"
SELECTED_RE = re.compile(r"^\s*(\d+)\s+(\d+)\s*$")
TIME_RE = re.compile(r"Time\s*=\s*([0-9.]+)\s+seconds")
PARTY_DATA_RE = re.compile(r"Data sent\s*=\s*([0-9.]+)\s+MB\s+in\s+~?(\d+)\s+rounds")
GLOBAL_DATA_RE = re.compile(r"Global data sent\s*=\s*([0-9.]+)\s+MB")


@dataclass(frozen=True)
class MPSPDZCandidateTopKConfig:
    mp_spdz_home: Path
    party_count: int
    topk: int
    candidate_capacity: int
    max_score: int = 10_000_000
    protocol: str = "semi"
    instance_dir: Path | None = None
    keep_instance: bool = False
    timeout_seconds: float = 300.0
    score_scale: int = 1_000_000
    share_mask: int = 1_000_000_000


@dataclass(frozen=True)
class MPSPDZCandidateTopKResult:
    selected_candidate_ids: list[str]
    selected_slots: list[int]
    metrics: dict[str, Any]


def rank_candidates_with_mpspdz(
    candidates: Sequence[dict[str, object]],
    config: MPSPDZCandidateTopKConfig,
) -> MPSPDZCandidateTopKResult:
    if config.protocol != "semi":
        raise ValueError("only MP-SPDZ semi protocol is currently wired for ranking-only validation")
    if config.party_count < 2:
        raise ValueError("party_count must be at least 2")
    if config.candidate_capacity < 1:
        raise ValueError("candidate_capacity must be positive")
    if len(candidates) > config.candidate_capacity:
        raise ValueError("candidate count exceeds candidate_capacity")

    ordered = sorted(candidates, key=lambda item: str(item["candidate_id"]))
    temp_context: tempfile.TemporaryDirectory[str] | None = None
    if config.instance_dir is None:
        temp_context = tempfile.TemporaryDirectory(prefix="fedkg-mpspdz-candidate-topk-")
        instance_dir = Path(temp_context.name)
    else:
        instance_dir = config.instance_dir
        instance_dir.mkdir(parents=True, exist_ok=True)

    started = time.perf_counter()
    try:
        _write_instance(ordered, config, instance_dir)
        stdout = _run_instance(config, instance_dir)
        selected_slots = _parse_selected_slots(stdout, sentinel=config.candidate_capacity)
        selected_ids = [
            str(ordered[slot]["candidate_id"])
            for slot in selected_slots
            if 0 <= slot < len(ordered)
        ]
        metrics = {
            **_parse_metrics(stdout),
            "ranking_wall_time_seconds": time.perf_counter() - started,
            "program": "secure_candidate_share_topk",
            "backend": "mp-spdz-semi",
            "candidate_capacity": config.candidate_capacity,
            "candidate_count": len(candidates),
            "party_count": config.party_count,
            "instance_dir": str(instance_dir) if config.keep_instance or config.instance_dir else None,
        }
        return MPSPDZCandidateTopKResult(selected_ids, selected_slots, metrics)
    finally:
        if temp_context is not None and not config.keep_instance:
            temp_context.cleanup()


def _write_instance(
    candidates: Sequence[dict[str, object]],
    config: MPSPDZCandidateTopKConfig,
    instance_dir: Path,
) -> None:
    player_dir = instance_dir / "Player-Data"
    player_dir.mkdir(parents=True, exist_ok=True)
    program = TEMPLATE.read_text().format(
        candidate_capacity=config.candidate_capacity,
        top_k=min(config.topk, config.candidate_capacity),
        party_count=config.party_count,
        max_score=config.max_score,
    )
    (instance_dir / "secure_candidate_share_topk.mpc").write_text(program)

    valid = [1 if slot < len(candidates) else 0 for slot in range(config.candidate_capacity)]
    scores = [
        int(round(float(candidates[slot]["score"]) * config.score_scale)) if slot < len(candidates) else 0
        for slot in range(config.candidate_capacity)
    ]
    support = [
        int(candidates[slot]["support"]) if slot < len(candidates) else 0
        for slot in range(config.candidate_capacity)
    ]
    if any(score < 0 or score > config.max_score for score in scores):
        raise ValueError("candidate score does not fit configured MP-SPDZ ranking max_score")
    if any(value < 0 for value in support):
        raise ValueError("candidate support must be non-negative")

    score_shares = [_integer_shares(value, config.party_count, config.share_mask) for value in scores]
    support_shares = [_integer_shares(value, config.party_count, config.share_mask) for value in support]

    for player in range(config.party_count):
        lines: list[str] = []
        if player == 0:
            lines.extend(str(value) for value in valid)
        for slot in range(config.candidate_capacity):
            lines.append(str(score_shares[slot][player]))
            lines.append(str(support_shares[slot][player]))
        (player_dir / f"Input-P{player}-0").write_text("\n".join(lines) + "\n")


def _integer_shares(value: int, share_count: int, mask: int) -> list[int]:
    shares = [random.randint(-mask, mask) for _ in range(share_count - 1)]
    shares.append(value - sum(shares))
    return shares


def _run_instance(config: MPSPDZCandidateTopKConfig, instance_dir: Path) -> str:
    mp_home = config.mp_spdz_home
    if not (mp_home / "compile.py").exists():
        raise FileNotFoundError(f"MP-SPDZ home does not contain compile.py: {mp_home}")

    program_name = "secure_candidate_share_topk"
    source_dir = mp_home / "Programs" / "Source"
    player_dir = mp_home / "Player-Data"
    source_dir.mkdir(parents=True, exist_ok=True)
    player_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(instance_dir / f"{program_name}.mpc", source_dir / f"{program_name}.mpc")
    for input_file in (instance_dir / "Player-Data").glob("Input-P*-0"):
        shutil.copy(input_file, player_dir / input_file.name)

    env = os.environ.copy()
    env["PLAYERS"] = str(config.party_count)
    compile_run = subprocess.run(
        ["./compile.py", program_name],
        cwd=mp_home,
        env=env,
        text=True,
        capture_output=True,
        timeout=config.timeout_seconds,
        check=False,
    )
    if compile_run.returncode != 0:
        raise RuntimeError(compile_run.stderr.strip() or compile_run.stdout.strip())
    run = subprocess.run(
        ["Scripts/semi.sh", program_name],
        cwd=mp_home,
        env=env,
        text=True,
        capture_output=True,
        timeout=config.timeout_seconds,
        check=False,
    )
    if run.returncode != 0:
        raise RuntimeError(run.stderr.strip() or run.stdout.strip())
    (instance_dir / "mp_spdz_output.txt").write_text(run.stdout)
    return run.stdout


def _parse_selected_slots(output: str, sentinel: int) -> list[int]:
    slots: list[int] = []
    in_table = False
    for line in output.splitlines():
        if line.strip() == "rank selected_candidate_slot":
            in_table = True
            continue
        if not in_table:
            continue
        match = SELECTED_RE.match(line)
        if not match:
            if slots:
                break
            continue
        slot = int(match.group(2))
        if slot != sentinel:
            slots.append(slot)
    return slots


def _parse_metrics(output: str) -> dict[str, Any]:
    time_match = TIME_RE.search(output)
    party_data_match = PARTY_DATA_RE.search(output)
    global_data_match = GLOBAL_DATA_RE.search(output)
    return {
        "mpc_time_seconds": float(time_match.group(1)) if time_match else None,
        "party0_data_mb": float(party_data_match.group(1)) if party_data_match else None,
        "rounds": int(party_data_match.group(2)) if party_data_match else None,
        "global_data_mb": float(global_data_match.group(1)) if global_data_match else None,
    }
