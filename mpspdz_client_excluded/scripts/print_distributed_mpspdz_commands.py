#!/usr/bin/env python3
"""Print MP-SPDZ commands for running a generated instance on separate hosts."""

from __future__ import annotations

import argparse
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--instance-dir", required=True)
    parser.add_argument("--mp-spdz-home", default="external/MP-SPDZ")
    parser.add_argument("--players", type=int, default=3)
    parser.add_argument("--host0", required=True, help="Hostname/IP reachable by all parties for startup coordination.")
    parser.add_argument("--port", type=int, default=14000)
    parser.add_argument("--protocol-binary", default="semi-party.x")
    args = parser.parse_args()

    instance_dir = Path(args.instance_dir)
    programs = sorted(instance_dir.glob("*.mpc"))
    if len(programs) != 1:
        raise SystemExit(f"expected exactly one .mpc program in {instance_dir}")
    program_name = programs[0].stem

    print("# Copy/prepare the common MPC program on every host:")
    print(f"cp {programs[0]} {args.mp_spdz_home}/Programs/Source/{program_name}.mpc")
    print(f"(cd {args.mp_spdz_home} && ./compile.py {program_name})")
    print()
    print("# Copy only each party's own input file to that party's host:")
    for player in range(args.players):
        input_file = instance_dir / "Player-Data" / f"Input-P{player}-0"
        print(f"# Party {player}:")
        print(f"mkdir -p {args.mp_spdz_home}/Player-Data")
        print(f"cp {input_file} {args.mp_spdz_home}/Player-Data/Input-P{player}-0")
        print()
    print("# Run these commands concurrently, one on each party host:")
    for player in range(args.players):
        print(
            f"cd {args.mp_spdz_home} && "
            f"./{args.protocol_binary} {player} {program_name} "
            f"-N {args.players} -h {args.host0} -pn {args.port}"
        )
    print()
    print("# Notes:")
    print("# - Party 0's host must be reachable at --host0:--port from the other parties.")
    print("# - Open the port range base..base+players if a firewall is enabled.")
    print("# - For encrypted channels, add -e and provision MP-SPDZ certificates/keys.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
