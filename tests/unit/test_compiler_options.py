from pathlib import Path

import pytest

from doram_t2_3pc.compiler_options import CompilerOptions
from doram_t2_3pc.io import write_private_lines


def test_optimized_compiler_defaults_match_the_pure_runner():
    options = CompilerOptions.from_environment({})
    command = options.command(
        Path("/opt/MP-SPDZ"),
        field_bits=124,
        field_prime=127,
        program_name="example",
    )
    assert command == [
        "/opt/MP-SPDZ/compile.py",
        "-F",
        "124",
        "-P",
        "127",
        "-b",
        "100000",
        "example",
    ]
    assert options.stamp_fields() == {
        "budget": 100000,
        "preserve_memory_order": False,
    }


def test_compiler_controls_are_explicit_and_validated():
    options = CompilerOptions.from_environment(
        {"MP_SPDZ_BUDGET": "25000", "MP_SPDZ_PRESERVE_MEM_ORDER": "1"}
    )
    command = options.command(
        Path("/m"), field_bits=64, field_prime=97, program_name="p"
    )
    assert command[-2:] == ["--preserve-mem-order", "p"]
    assert command[command.index("-b") + 1] == "25000"

    for environment in (
        {"MP_SPDZ_BUDGET": "0"},
        {"MP_SPDZ_BUDGET": "many"},
        {"MP_SPDZ_PRESERVE_MEM_ORDER": "yes"},
    ):
        with pytest.raises(ValueError):
            CompilerOptions.from_environment(environment)


def test_private_line_writer_streams_generators_atomically(tmp_path: Path):
    consumed: list[int] = []

    def values():
        for value in range(10_000):
            consumed.append(value)
            yield value

    output = tmp_path / "Input-P0-0"
    write_private_lines(output, values())
    assert consumed == list(range(10_000))
    assert output.read_text().splitlines() == [str(value) for value in range(10_000)]
    assert output.stat().st_mode & 0o077 == 0
