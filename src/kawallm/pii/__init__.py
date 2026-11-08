"""Deterministic, validated detectors for Indonesian PII."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import replace

from .bank import find_bank_account
from .base import PIIMatch, resolve_overlaps
from .bpjs import find_bpjs
from .identity import find_nip, find_nisn, find_passport, find_sim, validate_nip
from .network import find_ip
from .nik import find_nik, parse_nik, validate_nik
from .npwp import find_npwp, validate_npwp
from .phone import find_phone, phone_operator
from .plate import find_plate

EMAIL_RE = re.compile(r"(?<![\w.+-])[\w.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")


def find_email(text: str) -> list[PIIMatch]:
    if "@" not in text:
        return []
    return [PIIMatch("EMAIL", m.start(), m.end(), m.group(), 1.0) for m in EMAIL_RE.finditer(text)]


DETECTORS = {
    "ID_NIK": find_nik,
    "ID_NPWP": find_npwp,
    "ID_PHONE": find_phone,
    "ID_BANK_ACCOUNT": find_bank_account,
    "ID_BPJS": find_bpjs,
    "ID_PLATE": find_plate,
    "ID_NIP": find_nip,
    "ID_NISN": find_nisn,
    "ID_PASSPORT": find_passport,
    "ID_SIM": find_sim,
    "IP_ADDRESS": find_ip,
    "EMAIL": find_email,
}

ALL_ENTITIES = tuple(DETECTORS)

# Entity names that a detector emits, mapped to the detector key that produces them.
_DETECTOR_OF = {"ID_BPJS_KES": "ID_BPJS", "ID_BPJS_TK": "ID_BPJS"}

_DETECTORS_WITH_LOWER = {
    "ID_NPWP",
    "ID_BANK_ACCOUNT",
    "ID_BPJS",
    "ID_NISN",
    "ID_PASSPORT",
    "ID_SIM",
}

_DIGIT_RE = re.compile(r"\d")

# Invisible characters that can split a number ("0812\u200b34567890") without changing how it looks,
# including Unicode bidirectional formatting characters (\u202a-\u202e and \u2066-\u2069).
_INVISIBLE = re.compile(r"[\u00ad\u200b-\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]")


def detect_pii(text: str, entities: tuple[str, ...] | None = None, check_region: bool = True) -> list[PIIMatch]:
    """Run selected detectors and return non-overlapping matches sorted by position.

    ``check_region=False`` skips the Kemendagri region lookup for NIK (date and
    serial checks still apply). Invisible characters are dropped and compatibility
    forms are folded (NFKC, e.g. fullwidth digits) before detection; match positions
    always refer to the original text.
    """
    wanted = _resolve_entities(entities)
    if not text:
        return []
    cleaned, index = _normalized_view(text)
    if index is None:
        return _detect_core(text, wanted, entities, check_region)
    out = []
    for m in _detect_core(cleaned, wanted, entities, check_region):
        start, end = index[m.start], index[m.end - 1] + 1
        out.append(replace(m, start=start, end=end, text=text[start:end]))
    return out


def _normalized_view(text: str) -> tuple[str, list[int] | None]:
    """Text without invisible characters and with NFKC folded, plus the map back to the original positions.

    Returns ``(text, None)`` when nothing changes, so the common case costs no extra work.
    """
    if text.isascii():
        return text, None
    if not _INVISIBLE.search(text) and unicodedata.normalize("NFKC", text) == text:
        return text, None
    chars: list[str] = []
    index: list[int] = []
    for i, ch in enumerate(text):
        if _INVISIBLE.match(ch):
            continue
        for folded in unicodedata.normalize("NFKC", ch):
            chars.append(folded)
            index.append(i)
    index.append(len(text))
    return "".join(chars), index


def _detect_core(text: str, wanted: tuple[str, ...], entities, check_region: bool) -> list[PIIMatch]:
    has_digit = bool(_DIGIT_RE.search(text))
    has_at = "@" in text
    if not has_digit and not has_at:
        return []
    if not has_digit:
        if "EMAIL" not in wanted:
            return []
        return find_email(text)

    text_lower = text.lower()
    found: list[PIIMatch] = []
    for name in wanted:
        if name == "ID_NIK":
            found.extend(find_nik(text, check_region=check_region))
        elif name == "EMAIL":
            if has_at:
                found.extend(find_email(text))
        elif name in _DETECTORS_WITH_LOWER:
            found.extend(DETECTORS[name](text, text_lower=text_lower))
        else:
            found.extend(DETECTORS[name](text))
    if entities:  # a detector may emit more than was asked for (e.g. ID_BPJS_TK when only ID_BPJS_KES is wanted)
        found = [m for m in found if m.entity in entities or _DETECTOR_OF.get(m.entity) in entities]
    return resolve_overlaps(found)


def _resolve_entities(entities) -> tuple[str, ...]:
    """Detector keys to run for the requested entity names, without duplicates. Unknown names raise ValueError."""
    if not entities:
        return ALL_ENTITIES
    keys: dict[str, None] = {}
    for name in entities:
        key = _DETECTOR_OF.get(name, name)
        if key not in DETECTORS:
            known = sorted({*DETECTORS, *_DETECTOR_OF})
            raise ValueError(f"unknown entity {name!r}; expected one of {known}")
        keys[key] = None
    return tuple(keys)


__all__ = [
    "PIIMatch",
    "detect_pii",
    "find_nik",
    "parse_nik",
    "validate_nik",
    "find_npwp",
    "validate_npwp",
    "find_phone",
    "phone_operator",
    "find_bank_account",
    "find_bpjs",
    "find_plate",
    "find_nip",
    "find_nisn",
    "find_passport",
    "find_sim",
    "find_ip",
    "validate_nip",
    "find_email",
    "ALL_ENTITIES",
]
