"""Baseline constructions for paper-level comparison. NOT part of the
multi-party deployment path — evaluation reference points only.

1. TreeDpf2Party — a clean-room implementation of the standard two-party
   tree-based DPF (Boyle, Gilboa, Ishai, "Function Secret Sharing:
   Improvements and Extensions", ACM CCS 2016 / ePrint 2018/707, Figure 1:
   Gen*/Eval* with one correction word per level plus a final output
   correction), with additive output shares in Z/2^64. It is implemented in
   the same language (Python) and over the same PRG family (domain-separated
   SHAKE-256) as the multi-party path, so comparisons isolate the
   *construction* cost, not the toolchain. Its security model is the
   two-server non-collusion model (t=1 of 2) — strictly weaker than the
   honest-majority target — and it exists here only as the standard
   efficiency baseline. It shares no code or wire format with the deployed
   two-party CUDA CLI path (tools/fss_cli), which remains the deployed-path
   baseline and is benchmarked separately.

2. NaiveXorSharing — the trivial (N-1)-private scheme that additively
   (XOR-)shares the entire truth table of f_{alpha,beta} (BGI15 Section 3.1
   opening remark: key size 2^n * m). Information-theoretic; the key-size
   baseline every sublinear scheme is measured against.

3. PlaintextLookup — no privacy at all; the cost floor of a lookup.

Randomness: OS CSPRNG (secrets), as everywhere in this package.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

import numpy as np

from multiparty_fss.errors import ParameterError

_TREE_SEED_BYTES = 16
_TREE_EXPAND_DST = b"fedkg-mpfss-baseline/tree-dpf-bgi16/expand/v1\x00"
_TREE_CONVERT_DST = b"fedkg-mpfss-baseline/tree-dpf-bgi16/convert/v1\x00"
_MASK64 = (1 << 64) - 1


def _expand(seed: bytes) -> tuple[bytes, int, bytes, int]:
    """G(s) -> (sL, tL, sR, tR): two child seeds and two control bits."""
    shake = hashlib.shake_256()
    shake.update(_TREE_EXPAND_DST)
    shake.update(seed)
    buffer = shake.digest(34)
    return buffer[0:16], buffer[32] & 1, buffer[16:32], buffer[33] & 1


def _convert(seed: bytes) -> int:
    """Convert(s): pseudorandom element of Z/2^64 derived from the leaf seed."""
    shake = hashlib.shake_256()
    shake.update(_TREE_CONVERT_DST)
    shake.update(seed)
    return int.from_bytes(shake.digest(8), "little")


@dataclass(frozen=True)
class TreeDpfKey:
    party: int  # 0 or 1
    domain_bits: int
    seed: bytes
    # per-level correction words: (s_cw, t_cw_left, t_cw_right)
    correction_words: tuple[tuple[bytes, int, int], ...]
    output_correction: int  # CW^{(n+1)} in Z/2^64

    @property
    def key_bytes(self) -> int:
        return (
            _TREE_SEED_BYTES
            + len(self.correction_words) * (_TREE_SEED_BYTES + 1)
            + 8
            + 2
        )


class TreeDpf2Party:
    """Gen/Eval for the two-party tree DPF; combine = addition mod 2^64."""

    def __init__(self, domain_bits: int):
        if not 1 <= domain_bits <= 30:
            raise ParameterError("tree DPF baseline supports 1..30 domain bits")
        self.domain_bits = domain_bits

    def generate(self, alpha: int, beta: int) -> tuple[TreeDpfKey, TreeDpfKey]:
        n = self.domain_bits
        if not 0 <= alpha < (1 << n):
            raise ParameterError("alpha out of the input domain")
        if not 0 <= beta <= _MASK64:
            raise ParameterError("beta must be a 64-bit unsigned value")
        seeds = [secrets.token_bytes(_TREE_SEED_BYTES) for _ in range(2)]
        roots = (seeds[0], seeds[1])
        t = [0, 1]
        s = list(roots)
        correction_words: list[tuple[bytes, int, int]] = []
        for level in range(n):
            alpha_bit = (alpha >> (n - 1 - level)) & 1
            left0, tl0, right0, tr0 = _expand(s[0])
            left1, tl1, right1, tr1 = _expand(s[1])
            if alpha_bit == 0:
                keep0, keep_t0, lose0 = left0, tl0, right0
                keep1, keep_t1, lose1 = left1, tl1, right1
            else:
                keep0, keep_t0, lose0 = right0, tr0, left0
                keep1, keep_t1, lose1 = right1, tr1, left1
            s_cw = bytes(a ^ b for a, b in zip(lose0, lose1))
            t_cw_left = tl0 ^ tl1 ^ alpha_bit ^ 1
            t_cw_right = tr0 ^ tr1 ^ alpha_bit
            correction_words.append((s_cw, t_cw_left, t_cw_right))
            keep_t_cw = t_cw_right if alpha_bit else t_cw_left
            new_s, new_t = [], []
            for party, (keep, keep_t) in enumerate(((keep0, keep_t0), (keep1, keep_t1))):
                if t[party]:
                    keep = bytes(a ^ b for a, b in zip(keep, s_cw))
                    keep_t ^= keep_t_cw
                new_s.append(keep)
                new_t.append(keep_t)
            s, t = new_s, new_t
        sign = -1 if t[1] else 1
        output_correction = (
            sign * (beta - _convert(s[0]) + _convert(s[1]))
        ) % (1 << 64)
        return (
            TreeDpfKey(0, n, roots[0], tuple(correction_words), output_correction),
            TreeDpfKey(1, n, roots[1], tuple(correction_words), output_correction),
        )

    @staticmethod
    def evaluate(key: TreeDpfKey, point: int) -> int:
        n = key.domain_bits
        if not 0 <= point < (1 << n):
            raise ParameterError("evaluation point out of the input domain")
        s, t = key.seed, key.party
        for level in range(n):
            bit = (point >> (n - 1 - level)) & 1
            left, tl, right, tr = _expand(s)
            s_cw, t_cw_left, t_cw_right = key.correction_words[level]
            child_s, child_t = (right, tr) if bit else (left, tl)
            if t:
                s_cw_part = s_cw
                child_s = bytes(a ^ b for a, b in zip(child_s, s_cw_part))
                child_t ^= t_cw_right if bit else t_cw_left
            s, t = child_s, child_t
        value = (_convert(s) + t * key.output_correction) % (1 << 64)
        return value if key.party == 0 else (-value) % (1 << 64)

    @staticmethod
    def evaluate_full(key: TreeDpfKey, universe_size: int) -> np.ndarray:
        """Level-order full-domain evaluation (2^{n+1} PRG calls)."""
        n = key.domain_bits
        if not 0 < universe_size <= (1 << n):
            raise ParameterError("universe size out of the input domain")
        level_seeds: list[bytes] = [key.seed]
        level_bits: list[int] = [key.party]
        for level in range(n):
            s_cw, t_cw_left, t_cw_right = key.correction_words[level]
            next_seeds: list[bytes] = []
            next_bits: list[int] = []
            # Prune subtrees that cannot contain any rank < universe_size.
            span = 1 << (n - 1 - level)
            for index, (s, t) in enumerate(zip(level_seeds, level_bits)):
                left, tl, right, tr = _expand(s)
                if t:
                    left = bytes(a ^ b for a, b in zip(left, s_cw))
                    right = bytes(a ^ b for a, b in zip(right, s_cw))
                    tl ^= t_cw_left
                    tr ^= t_cw_right
                base = index * 2 * span
                if base < universe_size:
                    next_seeds.append(left)
                    next_bits.append(tl)
                if base + span < universe_size:
                    next_seeds.append(right)
                    next_bits.append(tr)
            level_seeds, level_bits = next_seeds, next_bits
        out = np.empty(universe_size, dtype="<u8")
        correction = key.output_correction
        for index in range(universe_size):
            value = (_convert(level_seeds[index]) + level_bits[index] * correction) % (
                1 << 64
            )
            out[index] = value if key.party == 0 else (-value) % (1 << 64)
        return out

    @staticmethod
    def combine(share_0: int, share_1: int) -> int:
        return (share_0 + share_1) % (1 << 64)


@dataclass(frozen=True)
class NaiveShareKey:
    party_index: int
    party_count: int
    domain_bits: int
    table: bytes  # 2^n little-endian uint64 words

    @property
    def key_bytes(self) -> int:
        return len(self.table)

    def vector(self) -> np.ndarray:
        return np.frombuffer(self.table, dtype="<u8")


class NaiveXorSharing:
    """(N-1)-private truth-table XOR sharing: the trivial baseline of BGI15."""

    def __init__(self, domain_bits: int, party_count: int):
        if not 1 <= domain_bits <= 24:
            raise ParameterError("naive baseline capped at 24 domain bits (2^n words)")
        if party_count < 2:
            raise ParameterError("naive sharing needs at least two parties")
        self.domain_bits = domain_bits
        self.party_count = party_count

    def generate(self, alpha: int, beta: int) -> list[NaiveShareKey]:
        size = 1 << self.domain_bits
        if not 0 <= alpha < size:
            raise ParameterError("alpha out of the input domain")
        target = np.zeros(size, dtype="<u8")
        target[alpha] = np.uint64(beta)
        shares = []
        accumulator = np.zeros(size, dtype="<u8")
        for _ in range(self.party_count - 1):
            vector = np.frombuffer(secrets.token_bytes(size * 8), dtype="<u8")
            shares.append(vector)
            accumulator = accumulator ^ vector
        shares.append(target ^ accumulator)
        return [
            NaiveShareKey(i, self.party_count, self.domain_bits, share.tobytes())
            for i, share in enumerate(shares)
        ]

    @staticmethod
    def evaluate(key: NaiveShareKey, point: int) -> int:
        return int(key.vector()[point])

    @staticmethod
    def evaluate_full(key: NaiveShareKey, universe_size: int) -> np.ndarray:
        return key.vector()[:universe_size].copy()


class PlaintextLookup:
    """No privacy: the cost floor. A dict lookup over the universe."""

    def __init__(self, points: list[str]):
        self.rank = {point: index for index, point in enumerate(points)}

    def lookup(self, point: str) -> int | None:
        return self.rank.get(point)
