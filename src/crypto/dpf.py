"""FSS/DPF backend contract.

This module intentionally does not include a toy DPF. A real backend must be
provided before claiming private lookup. A wrapper for myl7/fss or another FSS
implementation should implement this interface.
"""

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Protocol, Sequence


@dataclass(frozen=True)
class DpfKeyShare:
    party_id: str
    payload: Any


class DpfBackend(Protocol):
    def gen(self, alpha: str, beta: int, party_ids: Sequence[str]) -> Mapping[str, DpfKeyShare]:
        ...

    def eval(self, key_share: DpfKeyShare, point: str) -> int:
        ...


class UnconfiguredDpfBackend:
    """Fail-closed backend used until a real FSS/DPF implementation is wired."""

    def gen(self, alpha: str, beta: int, party_ids: Sequence[str]) -> Dict[str, DpfKeyShare]:
        raise NotImplementedError(
            "Real FSS/DPF backend required. Configure a myl7/fss wrapper before private lookup."
        )

    def eval(self, key_share: DpfKeyShare, point: str) -> int:
        raise NotImplementedError(
            "Real FSS/DPF backend required. Configure a myl7/fss wrapper before private lookup."
        )
