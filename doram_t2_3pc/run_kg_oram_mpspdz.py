"""Single-host harness for one bounded KG read-only-ORAM epoch.

This centralizes all three shares and is therefore an evaluation harness, not a
deployment of the non-collusion assumption.  It validates the preparation
manifest, compiles/stages first, and only then atomically consumes the epoch on
all three logical servers immediately before launch.
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
from .kg_oram_program import planned_shape, program_name, write_program
from .oram_epoch import KgOramEpochAuthorization, consume_epoch_once
from .protocols import DEFAULT_PROTOCOL, PROTOCOLS, resolve
from .relation_pages import RelationPageConfig


def _compile(
    home: Path,
    source: Path,
    name: str,
    config: RelationPageConfig,
    timeout: int,
) -> None:
    requested = CompilerOptions.from_environment()
    # Stash writes from earlier scheduled reads must be visible to later reads.
    # Permitting compiler memory reordering can break repeated-address handling.
    compiler = CompilerOptions(
        budget=requested.budget,
        preserve_memory_order=True,
    )
    destination = home / "Programs" / "Source" / source.name
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    stamp = {
        "source_sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
        "field_bits": config.base.field_usable_bits,
        "field_prime": config.base.field_prime,
        **compiler.stamp_fields(),
    }
    stamp_path = home / "Programs" / "Schedules" / f"{name}.kg-oram.json"
    schedule = home / "Programs" / "Schedules" / f"{name}.sch"
    if stamp_path.is_file() and schedule.is_file():
        try:
            if json.loads(stamp_path.read_text(encoding="utf-8")) == stamp:
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
    stamp_path.parent.mkdir(parents=True, exist_ok=True)
    stamp_path.write_text(json.dumps(stamp, sort_keys=True) + "\n", encoding="utf-8")


def run(
    instance_dir: str | Path,
    config_path: str | Path,
    mpspdz_home: str | Path,
    *,
    protocol: str = DEFAULT_PROTOCOL,
    log_label: str = "kg-oram",
    compile_timeout: int = 1800,
    runtime_timeout: int = 3600,
    allow_weaker_threat_model: bool = False,
) -> list[Path]:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,48}", log_label):
        raise ValueError("log_label must contain only letters, digits, '_' or '-'")
    instance = Path(instance_dir).resolve()
    config = RelationPageConfig.load(config_path)
    chosen = resolve(protocol, allow_weaker_threat_model=allow_weaker_threat_model)
    chosen.validate_field_prime(config.base.field_prime)
    home = Path(mpspdz_home).resolve()
    required = (home / "compile.py", home / "Scripts" / chosen.script, home / chosen.binary)
    if any(not path.is_file() for path in required):
        raise FileNotFoundError("MP-SPDZ compiler, protocol script, or party binary is missing")

    manifest = json.loads((instance / "manifest.json").read_text(encoding="utf-8"))
    authorization = KgOramEpochAuthorization(**manifest["epoch_authorization"])
    authorization.validate(
        config,
        epoch_id=authorization.epoch_id,
        query_count=authorization.query_count,
    )
    shape_options = manifest.get("shape_options", {
        "chi": int(manifest["shape"]["chi"]),
        "base_threshold": 64,
        "statistical_security_bits": 80,
    })
    shape_options = {key: int(value) for key, value in shape_options.items()}
    shape = planned_shape(config, authorization.query_count, **shape_options)
    if manifest["shape"] != {
        "levels": [vars(level) for level in shape.levels],
        "base_entries": shape.base_entries,
        "chi": shape.chi,
        "value_width": shape.value_width,
        "max_accesses": shape.max_accesses,
    }:
        raise ValueError("manifest ORAM shape does not match the public configuration")
    name = program_name(config, shape, authorization.query_count)
    if manifest["program"] != name:
        raise ValueError("manifest program identity does not match its config/shape")
    source = write_program(config, shape, authorization.query_count, instance / f"{name}.mpc")

    inputs = [instance / f"Input-P{server}-0" for server in range(3)]
    if any(not path.is_file() for path in inputs):
        raise FileNotFoundError("instance must contain exactly three private input files")
    expected_sizes = manifest.get("input_bytes_per_server")
    if expected_sizes != [path.stat().st_size for path in inputs]:
        raise ValueError("private input byte sizes do not match the preparation manifest")

    _compile(home, source, name, config, compile_timeout)
    player_data = home / "Player-Data"
    player_data.mkdir(mode=0o700, exist_ok=True)
    for server, path in enumerate(inputs):
        destination = player_data / f"Input-P{server}-0"
        shutil.copyfile(path, destination)
        os.chmod(destination, 0o600)

    log_dir = home / "logs"
    log_dir.mkdir(mode=0o700, exist_ok=True)
    prefix = f"{log_label}-"
    logs = [log_dir / f"{prefix}{name}-{server}" for server in range(3)]
    for path in logs:
        path.unlink(missing_ok=True)

    # Last reversible boundary: after these markers are created, rerunning this
    # instance correctly fails and owners must prepare fresh randomized shares.
    for server in range(3):
        consume_epoch_once(instance / "consumed", server, authorization)

    environment = os.environ.copy()
    environment.update({"PLAYERS": "3", "LOG_PREFIX": prefix})
    subprocess.run(
        [
            str(home / "Scripts" / chosen.script),
            name,
            "-OF", ".",
            "-P", str(config.base.field_prime),
        ],
        cwd=home,
        env=environment,
        check=True,
        timeout=runtime_timeout,
    )
    if any(not path.is_file() for path in logs):
        raise RuntimeError("MP-SPDZ completed without all three private output logs")
    return logs


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--instance-dir", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--mpspdz-home", required=True)
    parser.add_argument("--protocol", choices=sorted(PROTOCOLS), default=DEFAULT_PROTOCOL)
    parser.add_argument("--log-label", default="kg-oram")
    parser.add_argument("--compile-timeout", type=int, default=1800)
    parser.add_argument("--runtime-timeout", type=int, default=3600)
    parser.add_argument("--allow-weaker-threat-model", action="store_true")
    args = parser.parse_args()
    for path in run(
        args.instance_dir,
        args.config,
        args.mpspdz_home,
        protocol=args.protocol,
        log_label=args.log_label,
        compile_timeout=args.compile_timeout,
        runtime_timeout=args.runtime_timeout,
        allow_weaker_threat_model=args.allow_weaker_threat_model,
    ):
        print(path)


if __name__ == "__main__":
    main()
