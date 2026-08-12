from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
from pathlib import Path

from .config import PublicConfig
from .scan_program import program_name, write_program
from .sharing import SERVER_COUNT


def validate_private_input(
    config: PublicConfig,
    query_count: int,
    path: str | Path,
) -> None:
    expected = query_count * 3 + config.entity_count * config.block_edges
    observed = 0
    with Path(path).open("r", encoding="utf-8") as stream:
        for line in stream:
            observed += 1
            try:
                value = int(line)
            except ValueError as exc:
                raise ValueError("private server input contains a non-integer") from exc
            if not 0 <= value < config.field_prime:
                raise ValueError(
                    "private server input contains a non-canonical field element"
                )
    if observed != expected:
        raise ValueError(
            f"private server input has {observed} values; expected {expected}"
        )


def run_party(
    *,
    server_id: int,
    config_path: str | Path,
    query_count: int,
    private_input: str | Path,
    ip_file: str | Path,
    mpspdz_home: str | Path,
    output_log: str | Path,
    compile_timeout: int = 1800,
    runtime_timeout: int = 3600,
) -> Path:
    if server_id not in range(SERVER_COUNT):
        raise ValueError("server_id must be 0, 1, or 2")
    config = PublicConfig.load(config_path)
    validate_private_input(config, query_count, private_input)
    ip_path = Path(ip_file).resolve()
    if not ip_path.is_file():
        raise FileNotFoundError("MP-SPDZ IP file not found")
    home = Path(mpspdz_home).resolve()
    if any(
        not path.is_file() for path in (home / "compile.py", home / "semi-party.x")
    ):
        raise FileNotFoundError("MP-SPDZ must contain compile.py and semi-party.x")

    name = program_name(config, query_count)
    if not re.fullmatch(r"doram_scan_3pc_[0-9a-f]{16}", name):
        raise AssertionError("unsafe generated program name")
    write_program(config, query_count, home / "Programs" / "Source")

    player_data = home / "Player-Data"
    player_data.mkdir(parents=True, exist_ok=True)
    os.chmod(player_data, 0o700)
    destination = player_data / f"Input-P{server_id}-0"
    if destination.is_symlink():
        raise ValueError("refusing a symlink as the private input destination")
    shutil.copyfile(private_input, destination)
    os.chmod(destination, 0o600)

    subprocess.run(
        [
            str(home / "compile.py"),
            "-F",
            str(config.field_usable_bits),
            "-P",
            str(config.field_prime),
            "--preserve-mem-order",
            name,
        ],
        cwd=home,
        check=True,
        timeout=compile_timeout,
    )

    log = Path(output_log).resolve()
    log.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            subprocess.run(
                [
                    str(home / "semi-party.x"),
                    str(server_id),
                    name,
                    "-N",
                    str(SERVER_COUNT),
                    "-ip",
                    str(ip_path),
                    "-OF",
                    ".",
                    "-P",
                    str(config.field_prime),
                ],
                cwd=home,
                stdout=stream,
                stderr=subprocess.STDOUT,
                check=True,
                timeout=runtime_timeout,
            )
    finally:
        os.chmod(log, 0o600)
    return log


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run one distributed packed DORAM Semi party"
    )
    parser.add_argument("--server-id", type=int, required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--query-count", type=int, required=True)
    parser.add_argument("--private-input", required=True)
    parser.add_argument("--ip-file", required=True)
    parser.add_argument("--mpspdz-home", required=True)
    parser.add_argument("--output-log", required=True)
    parser.add_argument("--compile-timeout", type=int, default=1800)
    parser.add_argument("--runtime-timeout", type=int, default=3600)
    args = parser.parse_args()
    print(
        run_party(
            server_id=args.server_id,
            config_path=args.config,
            query_count=args.query_count,
            private_input=args.private_input,
            ip_file=args.ip_file,
            mpspdz_home=args.mpspdz_home,
            output_log=args.output_log,
            compile_timeout=args.compile_timeout,
            runtime_timeout=args.runtime_timeout,
        )
    )


if __name__ == "__main__":
    main()
