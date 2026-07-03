"""Load federated party data produced by the existing SimGRAG repository."""

import json
import pickle
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple


@dataclass(frozen=True)
class PartySpec:
    party_id: str
    config_path: Path
    data_path: Path


@dataclass(frozen=True)
class SimgragManifest:
    dataset: str
    base_config: Path
    parties: List[PartySpec]


def _resolve(path_value: str, base_dir: Path) -> Path:
    path = Path(path_value)
    return path if path.is_absolute() else (base_dir / path).resolve()


def load_manifest(path: str | Path) -> SimgragManifest:
    manifest_path = Path(path).resolve()
    payload = json.loads(manifest_path.read_text())
    base_dir = manifest_path.parent
    return SimgragManifest(
        dataset=payload["dataset"],
        base_config=_resolve(payload["base_config"], base_dir),
        parties=[
            PartySpec(
                party_id=spec["party_id"],
                config_path=_resolve(spec["config"], base_dir),
                data_path=_resolve(spec["data"], base_dir),
            )
            for spec in payload["parties"]
        ],
    )


def load_party_payload(path: str | Path) -> Tuple[Dict[str, Any], Dict[str, List[str]] | None]:
    with Path(path).open("rb") as handle:
        payload = pickle.load(handle)
    return payload["graph"], payload.get("types")
