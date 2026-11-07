"""Helpers for tests that deal with reversible placeholders like ``<ID_NIK_1_a3f2c9>``.

The 6-hex nonce is random per session, so tests compare the *shape* (nonce stripped) and take real
tokens from the masked text instead of hard-coding them.
"""

import re

TOKEN = re.compile(r"<(?:ID_[A-Z_]+|EMAIL)_\d+_[0-9a-f]{6}>")
_NONCE = re.compile(r"(<(?:ID_[A-Z_]+|EMAIL)_\d+)_[0-9a-f]{6}>")


def shape(text: str) -> str:
    """``'NIK <ID_NIK_1_a3f2c9>'`` -> ``'NIK <ID_NIK_1>'``."""
    return _NONCE.sub(r"\1>", text)


def tokens(text: str) -> list[str]:
    return TOKEN.findall(text)


def shape_map(mapping: dict[str, str]) -> dict[str, str]:
    return {shape(k): v for k, v in mapping.items()}


def token(masked: str, short: str) -> str:
    """The real token for a short name: ``token(masked, '<ID_NIK_1>')``."""
    for t in tokens(masked):
        if shape(t) == short:
            return t
    raise AssertionError(f"{short} not found in {masked!r}")
