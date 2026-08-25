from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any


def read_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_private_json(path: str | Path, value: Any) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def write_private_lines(path: str | Path, values: Iterable[int]) -> None:
    """Atomically write private integers without materialising a second copy.

    The previous implementation built one giant ``"\n".join(...)`` string.
    Relation-paged inputs can contain millions of field elements, so that
    temporarily doubled the resident representation of an already-large input.
    Bounded chunks retain atomic replacement while keeping serialization space
    independent of the total input length.
    """

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            chunk: list[str] = []
            for value in values:
                chunk.append(str(value))
                if len(chunk) == 4096:
                    stream.write("\n".join(chunk))
                    stream.write("\n")
                    chunk.clear()
            if chunk:
                stream.write("\n".join(chunk))
                stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
