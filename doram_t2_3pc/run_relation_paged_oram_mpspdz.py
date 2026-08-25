"""Single-host MP-SPDZ runner for one relation-paged dual-ORAM epoch."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
from dataclasses import asdict
from pathlib import Path

from .compiler_options import CompilerOptions
from .protocols import DEFAULT_PROTOCOL, PROTOCOLS, resolve
from .relation_paged_oram_epoch import (
    RelationPagedOramEpochAuthorization,
    consume_relation_paged_oram_epoch_once,
)
from .relation_paged_oram_program import planned_shape, program_name, write_program
from .relation_pages import RelationPageConfig


def _compile(
    home: Path,
    source: Path,
    name: str,
    config: RelationPageConfig,
    timeout: int,
) -> None:
    requested = CompilerOptions.from_environment()
    # The dual-stack circuit updates and subsequently reads per-level stashes.
    # MP-SPDZ otherwise warns that reordering memory instructions can change
    # semantics. Correctness takes priority over the much shorter schedule.
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
    stamp_path = home / "Programs" / "Schedules" / f"{name}.relation-paged-oram.json"
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
    log_label: str = "relation-paged-oram",
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
    if manifest.get("backend") != "relation-paged-recursive-readonly-oram":
        raise ValueError("instance manifest names another backend")
    authorization = RelationPagedOramEpochAuthorization(
        **manifest["epoch_authorization"]
    )
    authorization.validate(
        config,
        epoch_id=authorization.epoch_id,
        query_count=authorization.query_count,
    )
    shape_options = {
        key: int(value) for key, value in manifest["shape_options"].items()
    }
    shape = planned_shape(config, authorization.query_count, **shape_options)
    # JSON represents dataclass tuples as arrays/lists. Normalize the freshly
    # planned shape through the same serialization boundary before comparing;
    # comparing the raw ``asdict`` result would reject every valid manifest.
    canonical_shape = json.loads(json.dumps(asdict(shape)))
    if manifest["shape"] != canonical_shape:
        raise ValueError("manifest dual-ORAM shape does not match public configuration")
    name = program_name(config, shape, authorization.query_count)
    if manifest["program"] != name:
        raise ValueError("manifest program identity does not match config and shape")
    source = write_program(
        config, shape, authorization.query_count, instance / f"{name}.mpc"
    )
    inputs = [instance / f"Input-P{server}-0" for server in range(3)]
    if any(not path.is_file() for path in inputs):
        raise FileNotFoundError("instance requires three private input files")
    if manifest.get("input_bytes_per_server") != [path.stat().st_size for path in inputs]:
        raise ValueError("private input sizes do not match the manifest")

    # Compile before consuming the one-shot epoch, so compiler failures remain retryable.
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
    # Consume first. A replay must fail without deleting the completed run's
    # existing logs, which are the only client-side reconstruction evidence.
    for server in range(3):
        consume_relation_paged_oram_epoch_once(
            instance / "consumed", server, authorization
        )
    for path in logs:
        path.unlink(missing_ok=True)

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
        raise RuntimeError("MP-SPDZ completed without all three output logs")
    return logs


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--instance-dir", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--mpspdz-home", required=True)
    parser.add_argument("--protocol", choices=sorted(PROTOCOLS), default=DEFAULT_PROTOCOL)
    parser.add_argument("--log-label", default="relation-paged-oram")
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
