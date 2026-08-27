"""Parameters for the BGI15 p-party DPF (Gen^{p0} / Eval^{p0}).

Construction: Boyle, Gilboa, Ishai, "Function Secret Sharing", EUROCRYPT 2015,
Section 3.1 "A p-party protocol", Algorithms 3 and 4.
Official proceedings PDF:
https://www.iacr.org/archive/eurocrypt2015/90560300/90560300.pdf

Grid dimensions follow Algorithm 3 line 2 exactly:

    mu = ceil(2^{n/2} * 2^{(p-1)/2}) = ceil(sqrt(2^{n+p-1}))
    nu = ceil(2^n / mu)

computed in exact integer arithmetic (math.isqrt), never floating point.

The privacy threshold of the construction is p-1 (any strict coalition of key
holders; BGI15 Section 1.1 and Section 3.1). The `threshold` field records the
*claimed deployment bound* t, default floor((p-1)/2) (semi-honest honest
majority). Any 1 <= t <= p-1 is accepted because t-security for t <= p-1 is
implied by (p-1)-security (BGI15 Remark 2 item 1: t-security quantifies over
all coalitions of size <= t). Values above floor((p-1)/2) exceed the
honest-majority deployment model documented in multiparty_fss/SECURITY.md and
are never set by the integration layer.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass

from multiparty_fss.errors import ParameterError

CONSTRUCTION_ID = "bgi15-mpdpf-p0"
WIRE_VERSION_KEY = "fedkg-mpfss-key-v1"
WIRE_VERSION_REQUEST = "fedkg-mpfss-request-v1"
WIRE_VERSION_RESPONSE = "fedkg-mpfss-response-v1"
WIRE_VERSION_MANIFEST = "fedkg-mpfss-replica-manifest-v1"
OUTPUT_GROUP_ID = "xor64"  # GF(2)^64: 64-bit strings under bitwise XOR
PRG_ID = "shake256-v1"

SEED_BYTES = 16  # lambda = 128
OUTPUT_BITS = 64  # m = 64
MIN_PARTIES = 3  # N = 2 belongs to the legacy two-party path
MAX_PARTIES = 10  # key size scales with 2^{p-1}; cap keeps sizes reviewable
MIN_DOMAIN_BITS = 1
MAX_DOMAIN_BITS = 30  # key size scales with 2^{n/2}


def honest_majority_threshold(party_count: int) -> int:
    """t = floor((N - 1) / 2): the mandated honest-majority corruption bound."""
    return (party_count - 1) // 2


def _ceil_sqrt(value: int) -> int:
    root = math.isqrt(value)
    return root if root * root == value else root + 1


@dataclass(frozen=True)
class MpDpfParams:
    """Validated parameter set; immutable and hashable into params_id."""

    domain_bits: int  # n
    party_count: int  # p (= N evaluators)
    threshold: int  # claimed corruption bound t

    def __post_init__(self) -> None:
        if not isinstance(self.domain_bits, int) or isinstance(self.domain_bits, bool):
            raise ParameterError("domain_bits must be an integer")
        if not isinstance(self.party_count, int) or isinstance(self.party_count, bool):
            raise ParameterError("party_count must be an integer")
        if not isinstance(self.threshold, int) or isinstance(self.threshold, bool):
            raise ParameterError("threshold must be an integer")
        if not MIN_DOMAIN_BITS <= self.domain_bits <= MAX_DOMAIN_BITS:
            raise ParameterError(
                f"domain_bits must be in [{MIN_DOMAIN_BITS}, {MAX_DOMAIN_BITS}]; "
                f"got {self.domain_bits}"
            )
        if not MIN_PARTIES <= self.party_count <= MAX_PARTIES:
            raise ParameterError(
                f"party_count must be in [{MIN_PARTIES}, {MAX_PARTIES}] on the "
                f"multi-party path (N=2 is the legacy two-party path); got "
                f"{self.party_count}"
            )
        if not 1 <= self.threshold <= self.party_count - 1:
            raise ParameterError(
                "threshold must satisfy 1 <= t <= N-1 (the construction is "
                f"(N-1)-secure); got t={self.threshold} for N={self.party_count}"
            )

    @classmethod
    def create(
        cls,
        domain_bits: int,
        party_count: int,
        threshold: int | None = None,
    ) -> "MpDpfParams":
        if threshold is None:
            threshold = honest_majority_threshold(party_count)
        return cls(domain_bits=domain_bits, party_count=party_count, threshold=threshold)

    # -- derived quantities (Algorithm 3 line 2, exact integers) --

    @property
    def domain_size(self) -> int:
        return 1 << self.domain_bits

    @property
    def seeds_per_row(self) -> int:
        return 1 << (self.party_count - 1)  # 2^{p-1}

    @property
    def mu(self) -> int:
        return _ceil_sqrt(1 << (self.domain_bits + self.party_count - 1))

    @property
    def nu(self) -> int:
        return -(-self.domain_size // self.mu)  # ceil(2^n / mu)

    @property
    def sigma_bytes(self) -> int:
        return self.nu * self.seeds_per_row * SEED_BYTES

    @property
    def cw_bytes(self) -> int:
        return self.seeds_per_row * self.mu * (OUTPUT_BITS // 8)

    def cell(self, x: int) -> tuple[int, int]:
        """Row-major pair mapping (documented implementation convention for
        Algorithm 3 line 3 / Algorithm 4 line 3): gamma = x // mu, delta = x % mu."""
        if not 0 <= x < self.domain_size:
            raise ParameterError(f"domain point out of range [0, 2^{self.domain_bits})")
        return divmod(x, self.mu)

    def params_id(self) -> str:
        payload = {
            "construction": CONSTRUCTION_ID,
            "prg": PRG_ID,
            "output_group": OUTPUT_GROUP_ID,
            "seed_bytes": SEED_BYTES,
            "output_bits": OUTPUT_BITS,
            "domain_bits": self.domain_bits,
            "party_count": self.party_count,
            "threshold": self.threshold,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("ascii")).hexdigest()

    def prg_context(self) -> bytes:
        """Domain-separation prefix for the PRG G (see multiparty_fss/prg.py).

        Binds construction, wire generation, and the exact parameter set. Must
        NOT include party- or session-specific data: correctness requires every
        holder of a seed to expand it identically within one key generation.
        """
        header = b"fedkg-mpdpf/bgi15-eurocrypt2015/prg/v1\x00"
        fields = (
            self.domain_bits,
            self.party_count,
            self.mu,
            self.nu,
            OUTPUT_BITS,
            SEED_BYTES * 8,
        )
        return header + b"".join(value.to_bytes(4, "big") for value in fields)


def domain_bits_for_universe(universe_size: int) -> int:
    """n = ceil(log2(max(U, 2))): the rank-domain size for a shared universe."""
    if not isinstance(universe_size, int) or isinstance(universe_size, bool):
        raise ParameterError("universe size must be an integer")
    if universe_size < 1:
        raise ParameterError("universe must contain at least one point")
    bits = max(universe_size - 1, 1).bit_length()
    if bits > MAX_DOMAIN_BITS:
        raise ParameterError(
            f"universe of size {universe_size} needs {bits} domain bits; the "
            f"sqrt-key construction is capped at {MAX_DOMAIN_BITS} bits"
        )
    return bits
