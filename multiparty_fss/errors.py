"""Exception types for the multi-party FSS path.

Every rejection raises one of these; nothing in this package fails open.
Messages never include key material, seeds, correction words, alpha, or beta.
"""

from __future__ import annotations


class MultipartyFssError(ValueError):
    """Base class for all multi-party FSS validation and protocol errors."""


class ParameterError(MultipartyFssError):
    """Unsupported or inconsistent construction parameters (N, t, n, ...)."""


class KeyShareFormatError(MultipartyFssError):
    """Malformed, truncated, or wrong-construction serialized key share."""


class RequestValidationError(MultipartyFssError):
    """Evaluator request rejected (binding or identity mismatch)."""


class ResponseValidationError(MultipartyFssError):
    """Evaluator response rejected (binding, count, or consistency failure)."""


class CombineError(MultipartyFssError):
    """Output-share combination refused (missing/duplicate/mixed shares)."""


class DomainError(MultipartyFssError):
    """Universe/domain encoding failure (unknown point, size mismatch)."""


class ProjectionError(MultipartyFssError):
    """Candidate projection construction or application failure."""


class StoreError(MultipartyFssError):
    """Evaluator store or replication manifest failure."""
