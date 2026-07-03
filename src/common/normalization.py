"""Shared text normalization for secure identifiers."""


def normalize_text(value: object) -> str:
    """Return the canonical text form used by gateway and parties."""
    return " ".join(str(value).strip().casefold().split())


def is_unknown(value: object) -> bool:
    return "UNKNOWN" in str(value)


def extract_unknown_type(unknown_node: object) -> str:
    """Extract a type label from labels like 'UNKNOWN movie 1'."""
    words = str(unknown_node).replace("UNKNOWN", "", 1).strip().split()
    if words and words[-1].isdigit():
        words = words[:-1]
    return " ".join(words).strip()
