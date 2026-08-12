from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
from pathlib import Path

from .config import PublicConfig
from .program import program_name, write_program


PROTOCOL_SCRIPT = "semi.sh"


def run(instance_dir: str | Path, config_path: str | Path, mpspdz_home: str | Path) -> list[Path]:
    instance = Path(instance_dir).resolve()
    config = PublicConfig.load(config_path)
    home = Path(mpspdz_home).resolve()
    required = [home / "compile.py", home / "Scripts" / PROTOCOL_SCRIPT, home / "semi-party.x"]
    if any(not path.is_file() for path in required):
        raise FileNotFoundError("MP-SPDZ must contain compile.py, Scripts/semi.sh, and semi-party.x")
    inputs = [instance / f"Input-P{server}-0" for server in range(3)]
    if any(not path.is_file() for path in inputs):
        raise FileNotFoundError("instance must contain exactly Input-P0-0, Input-P1-0, Input-P2-0")
    extras = list(instance.glob("Input-P*-0"))
    if {path.name for path in extras} != {path.name for path in inputs}:
        raise ValueError("refusing an instance with a computation committee other than exactly three servers")

    name = program_name(config)
    if not re.fullmatch(r"doram_t2_3pc_[0-9a-f]{16}", name):
        raise AssertionError("unsafe program name")
    generated = write_program(config, instance)
    source = home / "Programs" / "Source" / generated.name
    player_data = home / "Player-Data"
    player_data.mkdir(parents=True, exist_ok=True)
    os.chmod(player_data, 0o700)
    shutil.copyfile(generated, source)
    for server, path in enumerate(inputs):
        destination = player_data / f"Input-P{server}-0"
        shutil.copyfile(path, destination)
        os.chmod(destination, 0o600)

    # Pin both the security protocol and arithmetic field. There is no option
    # to select Rep3, Shamir, emulation, or another weaker/mismatched backend.
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
    environment = os.environ.copy()
    environment["PLAYERS"] = "3"
    environment["LOG_PREFIX"] = "doram-t2-"
    logs = [home / "logs" / f"doram-t2-{name}-{server}" for server in range(3)]
    (home / "logs").mkdir(mode=0o700, exist_ok=True)
    os.chmod(home / "logs", 0o700)
    if any(path.exists() or path.is_symlink() for path in logs):
        raise FileExistsError("refusing to overwrite pre-existing private output logs")
    previous_umask = os.umask(0o077)
    try:
        subprocess.run(
            # `-OF .` enables party-specific print output on all three servers
            # while retaining the normal private input files. `-I` must not be
            # used because MP-SPDZ interprets it as interactive *input* too.
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
        description="Run only the 3-party semi-honest dishonest-majority MP-SPDZ backend"
    )
    parser.add_argument("--config", required=True)
    parser.add_argument("--instance-dir", required=True)
    parser.add_argument("--mpspdz-home", required=True)
    args = parser.parse_args()
    for path in run(args.instance_dir, args.config, args.mpspdz_home):
        print(path)


if __name__ == "__main__":
    main()
