"""Deterministic, validated detectors for Indonesian PII."""

from __future__ import annotations

import re

from .bank import find_bank_account
from .base import PIIMatch, resolve_overlaps
from .bpjs import find_bpjs
from .identity import find_nip, find_nisn, find_passport, find_sim, validate_nip
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
    "EMAIL": find_email,
}

ALL_ENTITIES = tuple(DETECTORS)


def detect_pii(text: str, entities: tuple[str, ...] | None = None, check_region: bool = True) -> list[PIIMatch]:
    """Run selected detectors and return non-overlapping matches sorted by position.

    ``check_region=False`` skips the Kemendagri region lookup for NIK (date and
    serial checks still apply).
    """
    if not text or not any(ch.isdigit() or ch == "@" or ch.isupper() for ch in text):
        return []
    found: list[PIIMatch] = []
    for name in entities or ALL_ENTITIES:
        if name == "ID_NIK":
            found.extend(find_nik(text, check_region=check_region))
        else:
            found.extend(DETECTORS[name](text))
    return resolve_overlaps(found)


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
    "validate_nip",
    "find_email",
    "ALL_ENTITIES",
]
