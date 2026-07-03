"""DPF input-domain projection helpers.

The current native FSS backend uses a 64-bit DPF input domain. HMAC IDs remain
256-bit hex strings, so every index build must check that the 64-bit projection
does not collide for the IDs that will be queried privately.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

DPF_DOMAIN_BITS = 64
DPF_DOMAIN_HEX_CHARS = DPF_DOMAIN_BITS // 4
DPF_MODULUS = 1 << DPF_DOMAIN_BITS
DPF_PROJECTION = "hmac_sha256_prefix64"


class DpfProjectionCollisionError(ValueError):
    pass


def project_hmac_id(encoded_id: str, hex_chars: int = DPF_DOMAIN_HEX_CHARS) -> str:
    value = encoded_id.lower().removeprefix("0x")
    if len(value) < hex_chars:
        raise ValueError(f"Encoded ID is too short for {hex_chars * 4}-bit DPF projection")
    if any(ch not in "0123456789abcdef" for ch in value):
        raise ValueError("Encoded ID must be hexadecimal")
    return value[:hex_chars]


@dataclass(frozen=True)
class ProjectionCollision:
    category: str
    projection: str
    first_id: str
    second_id: str
    first_label: str | None = None
    second_label: str | None = None


def find_projection_collisions(
    category: str,
    ids: Iterable[str] | Mapping[str, str],
) -> list[ProjectionCollision]:
    if isinstance(ids, Mapping):
        items = [(encoded_id, str(label)) for encoded_id, label in ids.items()]
    else:
        items = [(encoded_id, None) for encoded_id in ids]

    seen: dict[str, tuple[str, str | None]] = {}
    collisions: list[ProjectionCollision] = []
    for encoded_id, label in items:
        projection = project_hmac_id(encoded_id)
        existing = seen.get(projection)
        if existing is not None and existing[0] != encoded_id:
            collisions.append(
                ProjectionCollision(
                    category=category,
                    projection=projection,
                    first_id=existing[0],
                    second_id=encoded_id,
                    first_label=existing[1],
                    second_label=label,
                )
            )
        else:
            seen[projection] = (encoded_id, label)
    return collisions


def assert_no_projection_collisions(category: str, ids: Iterable[str] | Mapping[str, str]) -> None:
    collisions = find_projection_collisions(category, ids)
    if not collisions:
        return
    examples = "; ".join(
        f"{c.category}:{c.projection} maps {c.first_label or c.first_id} and {c.second_label or c.second_id}"
        for c in collisions[:5]
    )
    raise DpfProjectionCollisionError(
        f"Detected {len(collisions)} DPF projection collision(s) in {category}. "
        f"The 64-bit backend cannot be used safely for this index until the domain is widened. "
        f"Examples: {examples}"
    )
