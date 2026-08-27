"""PRG instantiation for BGI15 Algorithm 3/4: G : {0,1}^lambda -> {0,1}^{m*mu}.

Instantiated as the SHAKE-256 XOF (FIPS 202) applied to a domain-separation
context followed by the 128-bit seed, squeezed to exactly mu 64-bit words:

    G(s) = SHAKE256(params.prg_context() || s)[0 : 8*mu]

Assumption (documented, not proven here): SHAKE-256 with a uniformly random
128-bit seed suffix behaves as a pseudorandom generator. This stands in for
the abstract PRG of BGI15; the construction's security theorem is relative to
G being a PRG. SHAKE-256 is chosen because it is in the Python standard
library (no new dependency), has arbitrary-length output, and supports clean
domain separation. It is NOT the fastest possible choice (fixed-key AES would
be) — an acceptable trade for a reviewable research prototype.

The context (multiparty_fss/params.py: prg_context) binds construction ID,
scheme version, and the exact parameter set, so equal seed values under
different parameter sets or future construction revisions produce independent
streams. The context deliberately contains no party index, session ID, or
request data: correctness of the scheme requires every party holding seed
s_{gamma',j} to expand it to the identical string within one key generation.

Output layout: mu little-endian unsigned 64-bit words (numpy dtype '<u8').
"""

from __future__ import annotations

import hashlib

import numpy as np

from multiparty_fss.errors import ParameterError
from multiparty_fss.params import MpDpfParams, SEED_BYTES


def expand_seed(params: MpDpfParams, seed: bytes) -> np.ndarray:
    """G(seed) as a length-mu vector of uint64 words (read-only view)."""
    if len(seed) != SEED_BYTES:
        raise ParameterError("PRG seed must be exactly 16 bytes")
    shake = hashlib.shake_256()
    shake.update(params.prg_context())
    shake.update(seed)
    buffer = shake.digest(8 * params.mu)
    vector = np.frombuffer(buffer, dtype="<u8")
    return vector
