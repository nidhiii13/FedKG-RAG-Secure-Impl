"""HMAC-SHA256 deterministic identifiers for party-local secure indexes."""

import hashlib
import hmac
import os
from dataclasses import dataclass

from src.common.normalization import normalize_text

DEFAULT_ENV_VAR = "FEDKG_SETUP_KEY"


class MissingSetupKeyError(RuntimeError):
    pass


def load_setup_key(env_var: str = DEFAULT_ENV_VAR) -> bytes:
    value = os.environ.get(env_var)
    if not value:
        raise MissingSetupKeyError(
            f"Missing setup key. Set {env_var}; do not store it in the manifest or source code."
        )
    return value.encode("utf-8")


@dataclass(frozen=True)
class HmacIdProvider:
    setup_key: bytes
    digest_bytes: int = 32

    @classmethod
    def from_env(cls, env_var: str = DEFAULT_ENV_VAR) -> "HmacIdProvider":
        return cls(load_setup_key(env_var))

    def id_for(self, namespace: str, value: object) -> str:
        message = f"{namespace}:{normalize_text(value)}".encode("utf-8")
        digest = hmac.new(self.setup_key, message, hashlib.sha256).digest()
        return digest[: self.digest_bytes].hex()

    def entity_id(self, value: object) -> str:
        return self.id_for("entity", value)

    def relation_id(self, value: object) -> str:
        return self.id_for("relation", value)

    def type_id(self, value: object) -> str:
        return self.id_for("type", value)

    def relation_bucket_id(self, value: object) -> str:
        return self.id_for("relation_bucket", value)
