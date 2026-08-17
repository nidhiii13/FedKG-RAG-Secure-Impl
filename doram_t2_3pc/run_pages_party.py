"""Run one server of the EXPERIMENTAL relation-paged backend.

This is the deployment entry point. ``run_pages_mpspdz`` launches all three
parties on one host and therefore centralizes every share, which does not
instantiate the non-collusion assumption; only this module does, and only when
the three processes run on separately administered hosts that each receive
exclusively their own input and output shares.

The wrapper does not configure transport security. Shard delivery to the hosts
and log return to the client must use authenticated, encrypted channels
supplied by the deployment.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
from pathlib import Path

from .page_program import program_name, write_program
from .paged_shares import validate_private_input
from .protocols import DEFAULT_PROTOCOL, PROTOCOLS, resolve
from .relation_pages import RelationPageConfig
from .sharing import SERVER_COUNT


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
    protocol: str = DEFAULT_PROTOCOL,
    allow_weaker_threat_model: bool = False,
) -> Path:
    if server_id not in range(SERVER_COUNT):
        raise ValueError("server_id must be 0, 1, or 2")
    chosen = resolve(protocol, allow_weaker_threat_model=allow_weaker_threat_model)
    if chosen.weaker_than_declared:
        print(
            f"WARNING: running under {chosen.describe()}. This is WEAKER than "
            "the declared threat model; label every number it produces.",
            flush=True,
        )
    party_binary = chosen.binary
    config = RelationPageConfig.load(config_path)
    # Fail before contacting peers if this host was handed the wrong shard.
    validate_private_input(config, query_count, private_input)

    ip_path = Path(ip_file).resolve()
    if not ip_path.is_file():
        raise FileNotFoundError("MP-SPDZ IP file not found")
    home = Path(mpspdz_home).resolve()
    if any(
        not path.is_file() for path in (home / "compile.py", home / party_binary)
    ):
        raise FileNotFoundError(
            f"MP-SPDZ must contain compile.py and {party_binary}"
        )

    name = program_name(config, query_count)
    if not re.fullmatch(r"paged_kg_3pc_[0-9a-f]{16}", name):
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
            str(config.base.field_usable_bits),
            "-P",
            str(config.base.field_prime),
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
                    str(home / party_binary),
                    str(server_id),
                    name,
                    "-N",
                    str(SERVER_COUNT),
                    "-ip",
                    str(ip_path),
                    "-OF",
                    ".",
                    "-P",
                    str(config.base.field_prime),
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
        description="Run one distributed relation-paged Semi party"
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
            "Required to select a protocol tolerating fewer than the declared "
            "two corrupted servers."
        ),
    )
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
            protocol=args.protocol,
            allow_weaker_threat_model=args.allow_weaker_threat_model,
        )
    )


if __name__ == "__main__":
    main()
