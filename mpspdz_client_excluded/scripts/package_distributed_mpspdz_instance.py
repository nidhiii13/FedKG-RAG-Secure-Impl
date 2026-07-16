#!/usr/bin/env python3
"""Package a generated MP-SPDZ instance into per-party directories.

The generated instance contains all local test inputs together. This helper
splits it into deployment-shaped bundles where each party directory contains:

- the common .mpc source program;
- only that party's own Input-P{id}-0 file;
- a run command template for that party.
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--instance-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--players", type=int, default=3)
    parser.add_argument("--host0", required=True)
    parser.add_argument("--port", type=int, default=14000)
    parser.add_argument("--mp-spdz-home", default="external/MP-SPDZ")
    parser.add_argument("--protocol-binary", default="semi-party.x")
    args = parser.parse_args()

    instance_dir = Path(args.instance_dir)
    output_dir = Path(args.output_dir)
    programs = sorted(instance_dir.glob("*.mpc"))
    if len(programs) != 1:
        raise SystemExit(f"expected exactly one .mpc program in {instance_dir}")
    program = programs[0]
    program_name = program.stem

    output_dir.mkdir(parents=True, exist_ok=True)
    commands = []

    for player in range(args.players):
        party_dir = output_dir / f"party_{player}"
        source_dir = party_dir / "Programs" / "Source"
        input_dir = party_dir / "Player-Data"
        source_dir.mkdir(parents=True, exist_ok=True)
        input_dir.mkdir(parents=True, exist_ok=True)

        input_file = instance_dir / "Player-Data" / f"Input-P{player}-0"
        if not input_file.exists():
            raise SystemExit(f"missing input file for party {player}: {input_file}")

        shutil.copy2(program, source_dir / program.name)
        shutil.copy2(input_file, input_dir / input_file.name)

        run_command = (
            f"cd {args.mp_spdz_home} && "
            f"./compile.py {program_name} && "
            f"./{args.protocol_binary} {player} {program_name} "
            f"-N {args.players} -h {args.host0} -pn {args.port}"
        )
        (party_dir / "run_party.sh").write_text(f"#!/usr/bin/env bash\nset -euo pipefail\n{run_command}\n")
        commands.append({"party": player, "bundle": str(party_dir), "command": run_command})

    manifest = output_dir / "distributed_commands.txt"
    manifest.write_text(
        "\n\n".join(
            [
                f"party {item['party']} bundle: {item['bundle']}\n{item['command']}"
                for item in commands
            ]
        )
        + "\n"
    )

    print(f"packaged {args.players} party bundles under {output_dir}")
    print(f"commands: {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
