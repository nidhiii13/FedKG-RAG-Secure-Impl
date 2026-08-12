from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
from pathlib import Path

from .config import EDGE_FIELDS, PublicConfig
from .program import program_name, write_program


SERVER_COUNT = 3


def validate_private_input(config: PublicConfig, path: str | Path) -> None:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    expected = 3 + config.entity_count * len(config.owners) * config.fanout_per_owner * len(EDGE_FIELDS)
    if len(lines) != expected:
        raise ValueError(f"private server input has {len(lines)} values; expected {expected}")
    try:
        values = [int(line) for line in lines]
    except ValueError as exc:
        raise ValueError("private server input contains a non-integer") from exc
    if any(not 0 <= value < config.field_prime for value in values):
        raise ValueError("private server input contains a non-canonical field element")


def run_party(
    *,
    server_id: int,
    config_path: str | Path,
    private_input: str | Path,
    ip_file: str | Path,
    mpspdz_home: str | Path,
    output_log: str | Path,
) -> Path:
    if server_id not in range(SERVER_COUNT):
        raise ValueError("server_id must be 0, 1, or 2")
    config = PublicConfig.load(config_path)
    validate_private_input(config, private_input)
    ip_path = Path(ip_file).resolve()
    if not ip_path.is_file():
        raise FileNotFoundError("MP-SPDZ IP file not found")
    home = Path(mpspdz_home).resolve()
    required = [home / "compile.py", home / "semi-party.x"]
    if any(not path.is_file() for path in required):
        raise FileNotFoundError("MP-SPDZ must contain compile.py and semi-party.x")

    name = program_name(config)
    if not re.fullmatch(r"doram_t2_3pc_[0-9a-f]{16}", name):
        raise AssertionError("unsafe generated program name")
    write_program(config, home / "Programs" / "Source")
    player_data = home / "Player-Data"
    player_data.mkdir(parents=True, exist_ok=True)
    os.chmod(player_data, 0o700)
    destination = player_data / f"Input-P{server_id}-0"
    if destination.is_symlink():
        raise ValueError("refusing a symlink as the private MP-SPDZ input destination")
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
            )
    except BaseException:
        # Preserve a private diagnostic log on failure; it may contain a share.
        os.chmod(log, 0o600)
        raise
    os.chmod(log, 0o600)
    return log


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run one of three distributed Semi parties using only its own input shard"
    )
    parser.add_argument("--server-id", type=int, required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--private-input", required=True)
    parser.add_argument("--ip-file", required=True)
    parser.add_argument("--mpspdz-home", required=True)
    parser.add_argument("--output-log", required=True)
    args = parser.parse_args()
    print(
        run_party(
            server_id=args.server_id,
            config_path=args.config,
            private_input=args.private_input,
            ip_file=args.ip_file,
            mpspdz_home=args.mpspdz_home,
            output_log=args.output_log,
        )
    )


if __name__ == "__main__":
    main()
