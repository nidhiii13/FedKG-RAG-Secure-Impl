"""Shared MP-SPDZ compiler controls for the DORAM runners.

Large generated circuits are sensitive to compiler scheduling choices.  Keep
the memory-order barrier opt-in (matching the optimized PureMPSPDZ runner) and
put a finite budget on compiler optimization instead of forcing the most
memory-hungry settings on every run.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


@dataclass(frozen=True)
class CompilerOptions:
    budget: int = 100_000
    preserve_memory_order: bool = False

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str] | None = None
    ) -> "CompilerOptions":
        values = os.environ if environment is None else environment
        raw_budget = values.get("MP_SPDZ_BUDGET", "100000")
        try:
            budget = int(raw_budget)
        except ValueError as exc:
            raise ValueError("MP_SPDZ_BUDGET must be a positive integer") from exc
        if budget < 1:
            raise ValueError("MP_SPDZ_BUDGET must be a positive integer")
        raw_preserve = values.get("MP_SPDZ_PRESERVE_MEM_ORDER", "0")
        if raw_preserve not in {"0", "1"}:
            raise ValueError("MP_SPDZ_PRESERVE_MEM_ORDER must be 0 or 1")
        return cls(
            budget=budget,
            preserve_memory_order=raw_preserve == "1",
        )

    def command(
        self,
        home: Path,
        *,
        field_bits: int,
        field_prime: int,
        program_name: str,
    ) -> list[str]:
        command = [
            str(home / "compile.py"),
            "-F",
            str(field_bits),
            "-P",
            str(field_prime),
            "-b",
            str(self.budget),
        ]
        if self.preserve_memory_order:
            command.append("--preserve-mem-order")
        command.append(program_name)
        return command

    def stamp_fields(self) -> dict[str, int | bool]:
        return {
            "budget": self.budget,
            "preserve_memory_order": self.preserve_memory_order,
        }
