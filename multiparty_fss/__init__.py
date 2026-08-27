"""Configurable N-party FSS (distributed point function) path.

Construction: the p-party DPF of Boyle, Gilboa, Ishai, "Function Secret
Sharing", EUROCRYPT 2015, Section 3.1, Algorithms 3-4 (Gen^{p0}, Eval^{p0}).
Output group: GF(2)^64 (XOR). Claimed deployment threshold: semi-honest
honest majority, t = floor((N-1)/2); the construction itself is (N-1)-secure.

This package is deliberately separate from the two-party path (src/crypto,
src/runtime, tools/fss_cli), which remains unchanged. See README.md and
SECURITY.md in this directory, and docs/multiparty_fss/ at the repo root.
"""

from multiparty_fss.combine import combine, combine_vectors
from multiparty_fss.domain import UniverseDomain
from multiparty_fss.errors import (
    CombineError,
    DomainError,
    KeyShareFormatError,
    MultipartyFssError,
    ParameterError,
    ProjectionError,
    RequestValidationError,
    ResponseValidationError,
    StoreError,
)
from multiparty_fss.evaluate import evaluate, evaluate_many, evaluate_universe
from multiparty_fss.keygen import generate
from multiparty_fss.keyshare import (
    MpDpfKeyShare,
    deserialize_key_share,
    serialize_key_share,
)
from multiparty_fss.orchestrator import (
    MultipartyFssQueryOrchestrator,
    MultipartyFssQueryResult,
)
from multiparty_fss.params import (
    CONSTRUCTION_ID,
    MpDpfParams,
    domain_bits_for_universe,
    honest_majority_threshold,
)
from multiparty_fss.projection import (
    BuiltXorProjection,
    XorCandidateProjection,
    build_xor_projection,
)
from multiparty_fss.replication import (
    MpEvaluatorManifest,
    replicate_opaque_snapshots_multiparty,
    verify_multiparty_replicas,
)
from multiparty_fss.requests import (
    CombinedXorSlots,
    MpFssCoordinator,
    MpFssEvaluatorRequest,
    MpFssEvaluatorResponse,
)
from multiparty_fss.service import (
    MultipartyFssEvaluatorService,
    MultipartyFssEvaluatorStore,
)

__all__ = [
    "CONSTRUCTION_ID",
    "BuiltXorProjection",
    "CombineError",
    "CombinedXorSlots",
    "DomainError",
    "KeyShareFormatError",
    "MpDpfKeyShare",
    "MpDpfParams",
    "MpEvaluatorManifest",
    "MpFssCoordinator",
    "MpFssEvaluatorRequest",
    "MpFssEvaluatorResponse",
    "MultipartyFssError",
    "MultipartyFssEvaluatorService",
    "MultipartyFssEvaluatorStore",
    "MultipartyFssQueryOrchestrator",
    "MultipartyFssQueryResult",
    "ParameterError",
    "ProjectionError",
    "RequestValidationError",
    "ResponseValidationError",
    "StoreError",
    "UniverseDomain",
    "XorCandidateProjection",
    "build_xor_projection",
    "combine",
    "combine_vectors",
    "deserialize_key_share",
    "domain_bits_for_universe",
    "evaluate",
    "evaluate_many",
    "evaluate_universe",
    "generate",
    "honest_majority_threshold",
    "replicate_opaque_snapshots_multiparty",
    "serialize_key_share",
    "verify_multiparty_replicas",
]
