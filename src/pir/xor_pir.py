"""Replicated N-server XOR PIR over fixed-size byte records.

This is a simple information-theoretic PIR construction for replicated servers.
For database index i, the client creates N query bit-vectors whose XOR is the
unit vector e_i. Each server XORs all records selected by its bit-vector. The
client XORs all server answers to recover only record i.

Security model: a strict subset of servers learns no queried index from its own
uniform-looking query vector. If all servers collude, privacy is lost.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from typing import Sequence


def xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("xor inputs must have equal length")
    return bytes(a ^ b for a, b in zip(left, right))


@dataclass(frozen=True)
class FixedRecordDatabase:
    record_size: int
    records: tuple[bytes, ...]

    @classmethod
    def from_json_records(cls, payloads: Sequence[object], record_size: int) -> "FixedRecordDatabase":
        records = []
        for payload in payloads:
            encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            records.append(pad_record(encoded, record_size))
        return cls(record_size=record_size, records=tuple(records))

    @property
    def size(self) -> int:
        return len(self.records)


def pad_record(payload: bytes, record_size: int) -> bytes:
    if record_size < 1:
        raise ValueError("record_size must be positive")
    if len(payload) > record_size:
        raise ValueError(f"payload has {len(payload)} bytes; record_size is {record_size}")
    return payload + b"\x00" * (record_size - len(payload))


def unpad_record(record: bytes) -> bytes:
    return record.rstrip(b"\x00")


@dataclass(frozen=True)
class XorPirQuery:
    index: int
    server_vectors: tuple[tuple[int, ...], ...]


class XorPirClient:
    def __init__(self, server_count: int) -> None:
        if server_count < 2:
            raise ValueError("XOR PIR requires at least two replicated servers")
        self.server_count = server_count

    def create_query(self, index: int, database_size: int) -> XorPirQuery:
        if not 0 <= index < database_size:
            raise ValueError("query index out of database range")
        vectors: list[list[int]] = []
        accumulator = [0] * database_size
        for _ in range(self.server_count - 1):
            vector = [secrets.randbits(1) for _ in range(database_size)]
            vectors.append(vector)
            accumulator = [a ^ b for a, b in zip(accumulator, vector)]
        unit = [0] * database_size
        unit[index] = 1
        vectors.append([a ^ b for a, b in zip(accumulator, unit)])
        return XorPirQuery(index=index, server_vectors=tuple(tuple(v) for v in vectors))

    def recover(self, answers: Sequence[bytes]) -> bytes:
        if len(answers) != self.server_count:
            raise ValueError("answer count must match server count")
        result = answers[0]
        for answer in answers[1:]:
            result = xor_bytes(result, answer)
        return unpad_record(result)


class XorPirServer:
    def __init__(self, database: FixedRecordDatabase) -> None:
        self.database = database

    def answer(self, query_vector: Sequence[int]) -> bytes:
        if len(query_vector) != self.database.size:
            raise ValueError("query vector size must match database size")
        result = b"\x00" * self.database.record_size
        for bit, record in zip(query_vector, self.database.records):
            if bit:
                result = xor_bytes(result, record)
        return result
