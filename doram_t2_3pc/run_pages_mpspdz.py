"""Local three-party harness for the EXPERIMENTAL relation-paged backend.

Like ``run_scan_mpspdz``, this launches all three parties on one host and is a
correctness/performance tool only: it centralizes every share and therefore
does not instantiate the non-collusion assumption. A real deployment needs the
three inputs on three separately administered hosts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from .compiler_options import CompilerOptions
from .page_program import program_name, write_program
from .paged_shares import expected_private_input_values, validate_private_input
from .protocols import DEFAULT_PROTOCOL, PROTOCOLS, resolve
from .relation_pages import RelationPageConfig


def _compile_if_needed(
    home: Path,
    name: str,
    generated: Path,
    config: RelationPageConfig,
    timeout: int,
) -> None:
    compiler = CompilerOptions.from_environment()
    source = home / "Programs" / "Source" / generated.name
    source.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(generated, source)
    stamp_path = home / "Programs" / "Schedules" / f"{name}.pages.json"
    stamp_path.parent.mkdir(parents=True, exist_ok=True)
    expected_stamp = {
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "field_bits": config.base.field_usable_bits,
        "field_prime": config.base.field_prime,
        **compiler.stamp_fields(),
    }
    schedule = home / "Programs" / "Schedules" / f"{name}.sch"
    if stamp_path.is_file() and schedule.is_file():
        try:
            if json.loads(stamp_path.read_text(encoding="utf-8")) == expected_stamp:
                return
        except (OSError, ValueError):
            pass
    subprocess.run(
        compiler.command(
            home,
            field_bits=config.base.field_usable_bits,
            field_prime=config.base.field_prime,
            program_name=name,
        ),
        cwd=home,
        check=True,
        timeout=timeout,
    )
    stamp_path.write_text(json.dumps(expected_stamp, sort_keys=True) + "\n")


def run(
    instance_dir: str | Path,
    config_path: str | Path,
    query_count: int,
    mpspdz_home: str | Path,
    *,
    log_label: str = "paged-kg",
    compile_timeout: int = 1800,
    runtime_timeout: int = 3600,
    ablate_relation_check: bool = False,
    ablate_window_demux: bool = False,
    ablate_compaction: bool = False,
    ablate_folded_directory: bool = False,
    ablate_folded_residual: bool = False,
    ablate_owner_batching: bool = False,
    protocol: str = DEFAULT_PROTOCOL,
    allow_weaker_threat_model: bool = False,
) -> list[Path]:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,48}", log_label):
        raise ValueError("log_label must contain only letters, digits, '_' or '-'")
    chosen = resolve(protocol, allow_weaker_threat_model=allow_weaker_threat_model)
    if chosen.weaker_than_declared:
        # Make the downgrade visible in the run's own output, not just in the
        # command line that started it.
        print(
            f"WARNING: running under {chosen.describe()}. This is WEAKER than "
            "the declared threat model; label every number it produces.",
            flush=True,
        )
    instance = Path(instance_dir).resolve()
    config = RelationPageConfig.load(config_path)
    chosen.validate_field_prime(config.base.field_prime)
    home = Path(mpspdz_home).resolve()
    required = [
        home / "compile.py",
        home / "Scripts" / chosen.script,
        home / chosen.binary,
    ]
    if any(not path.is_file() for path in required):
        raise FileNotFoundError(
            f"MP-SPDZ must contain compile.py, Scripts/{chosen.script}, "
            f"and {chosen.binary}"
        )

    inputs = [instance / f"Input-P{server}-0" for server in range(3)]
    if any(not path.is_file() for path in inputs):
        raise FileNotFoundError(
            "instance must contain Input-P0-0, Input-P1-0, and Input-P2-0"
        )
    if {path.name for path in instance.glob("Input-P*-0")} != {
        path.name for path in inputs
    }:
        raise ValueError("the computation committee must contain exactly three servers")
    for path in inputs:
        validate_private_input(config, query_count, path)

    name = program_name(
        config,
        query_count,
        ablate_relation_check=ablate_relation_check,
        ablate_window_demux=ablate_window_demux,
        ablate_compaction=ablate_compaction,
        ablate_folded_directory=ablate_folded_directory,
        ablate_folded_residual=ablate_folded_residual,
        ablate_owner_batching=ablate_owner_batching,
    )
    if not re.fullmatch(r"paged_kg_3pc_[0-9a-f]{16}", name):
        raise AssertionError("unsafe generated program name")
    generated = write_program(
        config,
        query_count,
        instance,
        ablate_relation_check=ablate_relation_check,
        ablate_window_demux=ablate_window_demux,
        ablate_compaction=ablate_compaction,
        ablate_folded_directory=ablate_folded_directory,
        ablate_folded_residual=ablate_folded_residual,
        ablate_owner_batching=ablate_owner_batching,
    )

    player_data = home / "Player-Data"
    player_data.mkdir(parents=True, exist_ok=True)
    os.chmod(player_data, 0o700)
    for server, path in enumerate(inputs):
        destination = player_data / f"Input-P{server}-0"
        shutil.copyfile(path, destination)
        os.chmod(destination, 0o600)

    _compile_if_needed(home, name, generated, config, compile_timeout)

    log_dir = home / "logs"
    log_dir.mkdir(mode=0o700, exist_ok=True)
    prefix = f"{log_label}-"
    logs = [log_dir / f"{prefix}{name}-{server}" for server in range(3)]
    for path in logs:
        if path.exists() or path.is_symlink():
            path.unlink()

    environment = os.environ.copy()
    environment["PLAYERS"] = "3"
    environment["LOG_PREFIX"] = prefix
    previous_umask = os.umask(0o077)
    try:
        subprocess.run(
            [
                str(home / "Scripts" / chosen.script),
                name,
                "-OF",
                ".",
                "-P",
                str(config.base.field_prime),
            ],
            cwd=home,
            env=environment,
            check=True,
            timeout=runtime_timeout,
        )
    finally:
        os.umask(previous_umask)

    if any(not path.is_file() for path in logs):
        raise RuntimeError("MP-SPDZ completed without all three private output logs")
    for path in logs:
        os.chmod(path, 0o600)
    return logs


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the relation-paged circuit on three local MPC parties"
    )
    parser.add_argument("--config", required=True)
    parser.add_argument("--instance-dir", required=True)
    parser.add_argument("--query-count", required=True, type=int)
    parser.add_argument("--mpspdz-home", required=True)
    parser.add_argument("--log-label", default="paged-kg")
    parser.add_argument("--compile-timeout", type=int, default=1800)
    parser.add_argument("--runtime-timeout", type=int, default=3600)
    parser.add_argument(
        "--ablate-relation-check",
        action="store_true",
        help="ABLATION ONLY: restore the redundant first-hop relation test",
    )
    parser.add_argument(
        "--ablate-window-demux",
        action="store_true",
        help="ABLATION ONLY: one selector per page offset instead of a shared one",
    )
    parser.add_argument(
        "--ablate-folded-directory",
        action="store_true",
        help="ABLATION ONLY: read hop two at the combined entity*R+relation "
             "address instead of folding the shared relation out first",
    )
    parser.add_argument(
        "--ablate-folded-residual",
        action="store_true",
        help="ABLATION ONLY: repeat relation selection for every hop-two "
             "residual lookup instead of folding it once per query",
    )
    parser.add_argument(
        "--ablate-compaction",
        action="store_true",
        help="ABLATION ONLY: carry every first-hop slot into hop two uncompacted",
    )
    parser.add_argument(
        "--ablate-owner-batching",
        action="store_true",
        help="ABLATION ONLY: restore separate page resolution for each owner",
    )
    parser.add_argument(
        "--protocol",
        default=DEFAULT_PROTOCOL,
        choices=sorted(PROTOCOLS),
        help="; ".join(PROTOCOLS[key].describe() for key in sorted(PROTOCOLS)),
    )
    parser.add_argument(
        "--allow-weaker-threat-model",
        action="store_true",
        help=(
            "Required to select a protocol that tolerates fewer than the "
            "declared two corrupted servers. Every number produced under it "
            "must be labelled as a weaker-threat-model result."
        ),
    )
    args = parser.parse_args()
    print("expected private input values:",
          expected_private_input_values(
              RelationPageConfig.load(args.config), args.query_count
          ))
    for path in run(
        args.instance_dir,
        args.config,
        args.query_count,
        args.mpspdz_home,
        log_label=args.log_label,
        compile_timeout=args.compile_timeout,
        runtime_timeout=args.runtime_timeout,
        ablate_relation_check=args.ablate_relation_check,
        ablate_window_demux=args.ablate_window_demux,
        ablate_compaction=args.ablate_compaction,
        ablate_folded_directory=args.ablate_folded_directory,
        ablate_folded_residual=args.ablate_folded_residual,
        ablate_owner_batching=args.ablate_owner_batching,
        protocol=args.protocol,
        allow_weaker_threat_model=args.allow_weaker_threat_model,
    ):
        print(path)


if __name__ == "__main__":
    main()
