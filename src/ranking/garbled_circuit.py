"""Local n-party garbled-circuit ranking primitives.

This module implements garbled Boolean circuits for ranking comparisons over
values represented as n additive shares. It validates the algorithmic boundary
needed by n-party ranking: every candidate must carry one score/support share per
participating party, and only top-k candidate IDs leave the ranking interface.

The implementation is still local/single-process. It does not yet implement BMR
or another distributed n-party garbled-circuit protocol with network-separated
parties. It is the executable algorithm stage used before replacing the local
combiner with a production nPC backend.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Sequence

from src.aggregation.score_aggregation import CandidateShare
from src.aggregation.secret_sharing import AdditiveSharing
from src.ranking.secure_topk import SecureTopK

LABEL_BYTES = 16


def _label(select_bit: int) -> bytes:
    raw = bytearray(secrets.token_bytes(LABEL_BYTES))
    raw[-1] = (raw[-1] & 0xFE) | (select_bit & 1)
    return bytes(raw)


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def _gate_pad(gate_id: int, left: bytes, right: bytes) -> bytes:
    digest = hashlib.sha256()
    digest.update(gate_id.to_bytes(8, "big"))
    digest.update(left)
    digest.update(right)
    return digest.digest()[:LABEL_BYTES]


@dataclass(frozen=True)
class GarbledGate:
    gate_id: int
    left_wire: int
    right_wire: int
    output_wire: int
    table: tuple[bytes, bytes, bytes, bytes]


@dataclass
class GarbledBooleanCircuit:
    labels: Dict[int, tuple[bytes, bytes]] = field(default_factory=dict)
    gates: List[GarbledGate] = field(default_factory=list)
    output_wires: List[int] = field(default_factory=list)
    constant_labels: Dict[int, bytes] = field(default_factory=dict)
    _next_wire: int = 0
    _next_gate: int = 0

    def input_wire(self) -> int:
        wire = self._fresh_wire()
        self.labels[wire] = (_label(0), _label(1))
        return wire

    def const_wire(self, value: bool) -> int:
        wire = self._fresh_wire()
        self.labels[wire] = (_label(0), _label(1))
        self.constant_labels[wire] = self.labels[wire][int(value)]
        return wire

    def gate(self, left: int, right: int, truth: Callable[[int, int], int]) -> int:
        output = self._fresh_wire()
        self.labels[output] = (_label(0), _label(1))
        gate_id = self._next_gate
        self._next_gate += 1
        rows = [b""] * 4
        for a in (0, 1):
            for b in (0, 1):
                left_label = self.labels[left][a]
                right_label = self.labels[right][b]
                output_label = self.labels[output][truth(a, b)]
                index = ((left_label[-1] & 1) << 1) | (right_label[-1] & 1)
                rows[index] = _xor_bytes(output_label, _gate_pad(gate_id, left_label, right_label))
        self.gates.append(GarbledGate(gate_id, left, right, output, tuple(rows)))
        return output

    def and_gate(self, left: int, right: int) -> int:
        return self.gate(left, right, lambda a, b: a & b)

    def or_gate(self, left: int, right: int) -> int:
        return self.gate(left, right, lambda a, b: a | b)

    def xor_gate(self, left: int, right: int) -> int:
        return self.gate(left, right, lambda a, b: a ^ b)

    def not_gate(self, wire: int) -> int:
        return self.xor_gate(wire, self.const_wire(True))

    def encode_inputs(self, values: Dict[int, int]) -> Dict[int, bytes]:
        return {wire: self.labels[wire][int(bit)] for wire, bit in values.items()}

    def evaluate(self, encoded_inputs: Dict[int, bytes]) -> Dict[int, bytes]:
        values = dict(self.constant_labels)
        values.update(encoded_inputs)
        for gate in self.gates:
            left = values[gate.left_wire]
            right = values[gate.right_wire]
            index = ((left[-1] & 1) << 1) | (right[-1] & 1)
            values[gate.output_wire] = _xor_bytes(gate.table[index], _gate_pad(gate.gate_id, left, right))
        return {wire: values[wire] for wire in self.output_wires}

    def decode_output(self, wire: int, label: bytes) -> int:
        zero, one = self.labels[wire]
        if label == zero:
            return 0
        if label == one:
            return 1
        raise ValueError("invalid output label for garbled circuit")

    def _fresh_wire(self) -> int:
        wire = self._next_wire
        self._next_wire += 1
        return wire


def _int_to_bits(value: int, bit_width: int) -> list[int]:
    if value < 0:
        raise ValueError("garbled unsigned comparator requires non-negative values")
    if value >= (1 << bit_width):
        raise ValueError(f"value {value} does not fit in {bit_width} bits")
    return [(value >> index) & 1 for index in range(bit_width)]


def _less_than(circuit: GarbledBooleanCircuit, left_bits: Sequence[int], right_bits: Sequence[int]) -> tuple[int, int]:
    if len(left_bits) != len(right_bits):
        raise ValueError("comparison inputs must have the same bit width")
    eq = circuit.const_wire(True)
    lt = circuit.const_wire(False)
    for left, right in zip(reversed(left_bits), reversed(right_bits)):
        left_lt_right = circuit.and_gate(circuit.not_gate(left), right)
        lt_here = circuit.and_gate(eq, left_lt_right)
        lt = circuit.or_gate(lt, lt_here)
        different = circuit.xor_gate(left, right)
        eq = circuit.and_gate(eq, circuit.not_gate(different))
    return lt, eq


def garbled_rank_key_better(
    left_score: int,
    left_support: int,
    right_score: int,
    right_support: int,
    bit_width: int,
) -> bool:
    """Return true when the left candidate ranks before the right candidate.

    Ranking rule: lower score is better; if scores tie, higher support is better.
    The comparison rule is evaluated by a garbled Boolean circuit.
    """

    circuit = GarbledBooleanCircuit()
    left_score_wires = [circuit.input_wire() for _ in range(bit_width)]
    right_score_wires = [circuit.input_wire() for _ in range(bit_width)]
    left_support_wires = [circuit.input_wire() for _ in range(bit_width)]
    right_support_wires = [circuit.input_wire() for _ in range(bit_width)]

    score_lt, score_eq = _less_than(circuit, left_score_wires, right_score_wires)
    support_gt, _ = _less_than(circuit, right_support_wires, left_support_wires)
    tie_break = circuit.and_gate(score_eq, support_gt)
    better = circuit.or_gate(score_lt, tie_break)
    circuit.output_wires = [better]

    input_values: Dict[int, int] = {}
    for wires, value in (
        (left_score_wires, left_score),
        (right_score_wires, right_score),
        (left_support_wires, left_support),
        (right_support_wires, right_support),
    ):
        input_values.update(dict(zip(wires, _int_to_bits(value, bit_width))))

    outputs = circuit.evaluate(circuit.encode_inputs(input_values))
    return bool(circuit.decode_output(better, outputs[better]))


@dataclass(frozen=True)
class LocalGarbledCircuitTopK(SecureTopK):
    """Single-process n-party garbled-circuit top-k backend.

    Candidate scores and support counts enter as additive share vectors. When
    `party_count` is set, each candidate must carry exactly one score share and
    one support share per party. The local backend reconstructs those shares only
    to feed the garbled comparator; a production nPC backend should replace this
    local reconstruction with distributed share conversion/BMR-style evaluation.
    """

    sharing: AdditiveSharing = field(default_factory=AdditiveSharing)
    min_bit_width: int = 32
    party_count: int | None = None

    def rank(self, candidates: Sequence[CandidateShare], k: int) -> Sequence[str]:
        self._validate_candidates(candidates)
        ranked = self.rank_candidates(candidates)
        return [candidate.candidate_id for candidate in ranked[:k]]

    def rank_candidates(self, candidates: Sequence[CandidateShare]) -> list[CandidateShare]:
        self._validate_candidates(candidates)
        ranked: list[CandidateShare] = []
        for candidate in candidates:
            insert_at = len(ranked)
            for index, existing in enumerate(ranked):
                if self._candidate_better(candidate, existing):
                    insert_at = index
                    break
            ranked.insert(insert_at, candidate)
        return ranked

    def _validate_candidates(self, candidates: Sequence[CandidateShare]) -> None:
        if self.party_count is None:
            return
        if self.party_count < 2:
            raise ValueError("party_count must be at least 2 for n-party ranking")
        for candidate in candidates:
            if len(candidate.score_shares) != self.party_count:
                raise ValueError(
                    f"candidate {candidate.candidate_id} has {len(candidate.score_shares)} score shares; "
                    f"expected {self.party_count}"
                )
            if len(candidate.support_shares) != self.party_count:
                raise ValueError(
                    f"candidate {candidate.candidate_id} has {len(candidate.support_shares)} support shares; "
                    f"expected {self.party_count}"
                )

    def _candidate_better(self, left: CandidateShare, right: CandidateShare) -> bool:
        left_score, left_support = self._rank_values(left)
        right_score, right_support = self._rank_values(right)
        bit_width = max(
            self.min_bit_width,
            left_score.bit_length() + 1,
            right_score.bit_length() + 1,
            left_support.bit_length() + 1,
            right_support.bit_length() + 1,
        )
        if (left_score, left_support) == (right_score, right_support):
            return left.candidate_id < right.candidate_id
        return garbled_rank_key_better(left_score, left_support, right_score, right_support, bit_width)

    def _rank_values(self, candidate: CandidateShare) -> tuple[int, int]:
        score = self.sharing.combine(candidate.score_shares)
        support = self.sharing.combine(candidate.support_shares)
        if score > self.sharing.field // 2:
            score -= self.sharing.field
        if support > self.sharing.field // 2:
            support -= self.sharing.field
        if score < 0 or support < 0:
            raise ValueError("garbled top-k currently expects non-negative score and support values")
        return score, support
