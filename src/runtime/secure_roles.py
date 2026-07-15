"""Deployment roles for the hybrid two-party FSS and n-aggregator Prio design."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


@dataclass(frozen=True)
class ServiceRole:
    role_id: str
    authority: str
    endpoint: str

    @classmethod
    def from_mapping(cls, payload: Mapping[str, object]) -> "ServiceRole":
        values = {name: payload.get(name) for name in ("role_id", "authority", "endpoint")}
        if not all(isinstance(value, str) and value for value in values.values()):
            raise ValueError("service roles require non-empty role_id, authority, and endpoint")
        return cls(**values)  # type: ignore[arg-type]


@dataclass(frozen=True)
class SecureRoleTopology:
    data_parties: tuple[ServiceRole, ...]
    fss_evaluators: tuple[ServiceRole, ...]
    prio_aggregators: tuple[ServiceRole, ...]
    local_simulation: bool = False

    @classmethod
    def from_json(cls, path: str | Path) -> "SecureRoleTopology":
        payload = json.loads(Path(path).read_text())
        if not isinstance(payload, dict):
            raise ValueError("role topology must be a JSON object")
        return cls.from_mapping(payload)

    @classmethod
    def from_mapping(cls, payload: Mapping[str, object]) -> "SecureRoleTopology":
        def roles(name: str) -> tuple[ServiceRole, ...]:
            items = payload.get(name)
            if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
                raise ValueError(f"{name} must be an array of role objects")
            return tuple(ServiceRole.from_mapping(item) for item in items)

        local_simulation = payload.get("local_simulation", False)
        if not isinstance(local_simulation, bool):
            raise ValueError("local_simulation must be a boolean")
        topology = cls(
            data_parties=roles("data_parties"),
            fss_evaluators=roles("fss_evaluators"),
            prio_aggregators=roles("prio_aggregators"),
            local_simulation=local_simulation,
        )
        topology.validate()
        return topology

    @property
    def data_party_ids(self) -> tuple[str, ...]:
        return tuple(role.role_id for role in self.data_parties)

    @property
    def fss_evaluator_ids(self) -> tuple[str, ...]:
        return tuple(role.role_id for role in self.fss_evaluators)

    @property
    def prio_aggregator_ids(self) -> tuple[str, ...]:
        return tuple(role.role_id for role in self.prio_aggregators)

    def validate(self) -> None:
        if not self.data_parties:
            raise ValueError("at least one data party is required")
        if len(self.fss_evaluators) != 2:
            raise ValueError("the native DPF/FSS backend requires exactly two evaluator roles")
        if len(self.prio_aggregators) < 2:
            raise ValueError("Prio3 requires at least two aggregator roles")
        self._require_unique_ids(self.data_parties, "data party")
        self._require_unique_ids(self.fss_evaluators, "FSS evaluator")
        self._require_unique_ids(self.prio_aggregators, "Prio aggregator")

        all_roles = self.data_parties + self.fss_evaluators + self.prio_aggregators
        self._require_unique_ids(all_roles, "cross-role")
        if self.local_simulation:
            return
        if len({role.authority for role in self.fss_evaluators}) != 2:
            raise ValueError("production FSS evaluators must have independent authorities")
        if len({role.authority for role in self.prio_aggregators}) < 2:
            raise ValueError("production Prio aggregators require at least two authorities")
        if any(role.endpoint.startswith("local://") for role in all_roles):
            raise ValueError("local:// endpoints are allowed only in local_simulation mode")

    def validate_contributor_ids(self, contributor_ids: Sequence[str]) -> None:
        supplied = set(contributor_ids)
        expected = set(self.data_party_ids)
        if supplied != expected or len(contributor_ids) != len(expected):
            missing = sorted(expected - supplied)
            unexpected = sorted(supplied - expected)
            raise ValueError(
                f"candidate contributors do not match topology; missing={missing}, unexpected={unexpected}"
            )

    @staticmethod
    def _require_unique_ids(roles: Sequence[ServiceRole], label: str) -> None:
        role_ids = [role.role_id for role in roles]
        if len(role_ids) != len(set(role_ids)):
            raise ValueError(f"{label} role IDs must be unique")

