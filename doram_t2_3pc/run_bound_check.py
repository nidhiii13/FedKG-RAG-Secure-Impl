"""Run the one-time federation-wide bound check on three local parties.

Like the other single-host runners this centralizes every share and is a
correctness/measurement tool only; it does not instantiate the non-collusion
assumption. A real preparation phase runs the three parties on the three
separately administered hosts, exactly as ``run_pages_party`` does for
retrieval.

The check must pass before any layout declaring ``global_frontier`` is used. A
non-zero violation count means the declared bound is too small and the retrieval
circuit would silently drop matches at the second hop.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
from pathlib import Path

from .bound_check_program import program_name, write_program
from .protocols import DEFAULT_PROTOCOL, PROTOCOLS, resolve
from .relation_pages import RelationPageConfig


VIOLATIONS = re.compile(r"PAGED_BOUND_VIOLATIONS\s+(-?\d+)")


def run(
    instance_dir: str | Path,
    config_path: str | Path,
    mpspdz_home: str | Path,
    *,
    log_label: str = "paged-bound-check",
    compile_timeout: int = 1800,
    runtime_timeout: int = 3600,
    protocol: str = DEFAULT_PROTOCOL,
    allow_weaker_threat_model: bool = False,
) -> int:
    """Return the number of keys exceeding the declared bound (0 means valid)."""

    if not re.fullmatch(r"[A-Za-z0-9_-]{1,48}", log_label):
        raise ValueError("log_label must contain only letters, digits, '_' or '-'")
    chosen = resolve(protocol, allow_weaker_threat_model=allow_weaker_threat_model)
    if chosen.weaker_than_declared:
        print(
            f"WARNING: running under {chosen.describe()}. This is WEAKER than "
            "the declared threat model.",
            flush=True,
        )
    config = RelationPageConfig.load(config_path)
    instance = Path(instance_dir).resolve()
    home = Path(mpspdz_home).resolve()

    inputs = [instance / f"Input-P{server}-0" for server in range(3)]
    if any(not path.is_file() for path in inputs):
        raise FileNotFoundError(
            "instance must contain Input-P0-0, Input-P1-0, and Input-P2-0"
        )
    for path in inputs:
        lines = path.read_text(encoding="utf-8").split()
        if len(lines) != config.directory_rows:
            raise ValueError(
                f"{path} has {len(lines)} values; expected "
                f"{config.directory_rows}"
            )

    name = program_name(config)
    if not re.fullmatch(r"paged_bound_check_[0-9a-f]{16}", name):
        raise AssertionError("unsafe generated program name")
    generated = write_program(config, instance)
    source = home / "Programs" / "Source" / generated.name
    source.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(generated, source)

    player_data = home / "Player-Data"
    player_data.mkdir(parents=True, exist_ok=True)
    os.chmod(player_data, 0o700)
    for server, path in enumerate(inputs):
        destination = player_data / f"Input-P{server}-0"
        shutil.copyfile(path, destination)
        os.chmod(destination, 0o600)

    subprocess.run(
        [
            str(home / "compile.py"),
            "-F",
            str(config.base.field_usable_bits),
            "-P",
            str(config.base.field_prime),
            name,
        ],
        cwd=home,
        check=True,
        timeout=compile_timeout,
    )

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

    # Every server receives the same aggregate; disagreement means a corrupted
    # run rather than an overflowing layout, so it is an error, not a verdict.
    results = set()
    for path in logs:
        match = VIOLATIONS.search(path.read_text(encoding="utf-8"))
        if match is None:
            raise RuntimeError(f"no bound-check result in {path}")
        results.add(int(match.group(1)))
    if len(results) != 1:
        raise RuntimeError(f"servers disagree on the bound check: {sorted(results)}")
    return results.pop()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify a layout's federation-wide global_frontier bound"
    )
    parser.add_argument("--config", required=True)
    parser.add_argument("--instance-dir", required=True)
    parser.add_argument("--mpspdz-home", required=True)
    parser.add_argument("--log-label", default="paged-bound-check")
    parser.add_argument("--compile-timeout", type=int, default=1800)
    parser.add_argument("--runtime-timeout", type=int, default=3600)
    parser.add_argument(
        "--protocol", default=DEFAULT_PROTOCOL, choices=sorted(PROTOCOLS)
    )
    parser.add_argument("--allow-weaker-threat-model", action="store_true")
    args = parser.parse_args()
    violations = run(
        args.instance_dir,
        args.config,
        args.mpspdz_home,
        log_label=args.log_label,
        compile_timeout=args.compile_timeout,
        runtime_timeout=args.runtime_timeout,
        protocol=args.protocol,
        allow_weaker_threat_model=args.allow_weaker_threat_model,
    )
    if violations:
        print(
            f"REJECT: {violations} (source, relation) key(s) exceed the declared "
            "global_frontier. The retrieval circuit would silently drop matches; "
            "raise global_frontier and re-share."
        )
        return 1
    print("ACCEPT: every key is within the declared global_frontier.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
