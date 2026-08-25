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
from .config import PublicConfig
from .run_mpspdz import PROTOCOL_SCRIPT
from .scan_program import program_name, write_program


def _line_count(path: Path) -> int:
    with path.open("r", encoding="utf-8") as stream:
        return sum(1 for _ in stream)


def _compile_if_needed(
    home: Path,
    name: str,
    generated: Path,
    config: PublicConfig,
    timeout: int,
) -> None:
    compiler = CompilerOptions.from_environment()
    source = home / "Programs" / "Source" / generated.name
    shutil.copyfile(generated, source)
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    stamp_path = home / "Programs" / "Schedules" / f"{name}.scan.json"
    expected_stamp = {
        "source_sha256": source_hash,
        "field_bits": config.field_usable_bits,
        "field_prime": config.field_prime,
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
            field_bits=config.field_usable_bits,
            field_prime=config.field_prime,
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
    log_label: str = "doram-scan",
    compile_timeout: int = 1800,
    runtime_timeout: int = 3600,
) -> list[Path]:
    """Run the local three-party packed-scan harness.

    This launches all parties on one host and is intended for correctness and
    performance experiments, not as a non-colluding production deployment.
    """
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,48}", log_label):
        raise ValueError("log_label must contain only letters, digits, '_' or '-'")
    instance = Path(instance_dir).resolve()
    config = PublicConfig.load(config_path)
    home = Path(mpspdz_home).resolve()
    required = [
        home / "compile.py",
        home / "Scripts" / PROTOCOL_SCRIPT,
        home / "semi-party.x",
    ]
    if any(not path.is_file() for path in required):
        raise FileNotFoundError(
            "MP-SPDZ must contain compile.py, Scripts/semi.sh, and semi-party.x"
        )

    inputs = [instance / f"Input-P{server}-0" for server in range(3)]
    if any(not path.is_file() for path in inputs):
        raise FileNotFoundError(
            "instance must contain Input-P0-0, Input-P1-0, and Input-P2-0"
        )
    extras = list(instance.glob("Input-P*-0"))
    if {path.name for path in extras} != {path.name for path in inputs}:
        raise ValueError("the computation committee must contain exactly three servers")
    expected_values = query_count * 3 + config.entity_count * config.block_edges
    for path in inputs:
        observed = _line_count(path)
        if observed != expected_values:
            raise ValueError(
                f"{path} contains {observed} values; expected {expected_values}"
            )

    name = program_name(config, query_count)
    if not re.fullmatch(r"doram_scan_3pc_[0-9a-f]{16}", name):
        raise AssertionError("unsafe generated program name")
    generated = write_program(config, query_count, instance)

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
    os.chmod(log_dir, 0o700)
    prefix = f"{log_label}-"
    logs = [log_dir / f"{prefix}{name}-{server}" for server in range(3)]
    if any(path.exists() or path.is_symlink() for path in logs):
        raise FileExistsError("refusing to overwrite pre-existing private output logs")

    environment = os.environ.copy()
    environment["PLAYERS"] = "3"
    environment["LOG_PREFIX"] = prefix
    previous_umask = os.umask(0o077)
    try:
        subprocess.run(
            [
                str(home / "Scripts" / PROTOCOL_SCRIPT),
                name,
                "-OF",
                ".",
                "-P",
                str(config.field_prime),
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
        description=(
            "Run the fixed-batch packed MPC-oblivious scan on three local "
            "Semi parties"
        )
    )
    parser.add_argument("--config", required=True)
    parser.add_argument("--instance-dir", required=True)
    parser.add_argument("--query-count", required=True, type=int)
    parser.add_argument("--mpspdz-home", required=True)
    parser.add_argument("--log-label", default="doram-scan")
    parser.add_argument("--compile-timeout", type=int, default=1800)
    parser.add_argument("--runtime-timeout", type=int, default=3600)
    args = parser.parse_args()
    for path in run(
        args.instance_dir,
        args.config,
        args.query_count,
        args.mpspdz_home,
        log_label=args.log_label,
        compile_timeout=args.compile_timeout,
        runtime_timeout=args.runtime_timeout,
    ):
        print(path)


if __name__ == "__main__":
    main()
