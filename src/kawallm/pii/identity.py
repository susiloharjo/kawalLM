"""Other Indonesian identity numbers: NIP (civil servant), NISN (student), passport and SIM (driving licence).

NIP has a self-validating structure and is reported on its own. The others have no checksum, so
they are only reported when a keyword sits next to the number (same policy as BPJS and bank accounts).

NIP, 18 digits (BKN): birth date ``YYYYMMDD`` + appointment month ``YYYYMM`` + gender ``1``/``2`` + serial ``NNN``.
NISN, 10 digits (Kemendikbudristek). Passport: one uppercase letter + 7 digits. SIM: 12 digits.
"""

from __future__ import annotations

import re
from datetime import date

from .base import PIIMatch, digits_only, has_keyword_near, mentions_any

_SEP = r"[\s.\-]?"
NIP_RE = re.compile(rf"(?<![\d])(\d{{8}}){_SEP}(\d{{6}}){_SEP}([12]){_SEP}(\d{{3}})(?![\d])")
NISN_RE = re.compile(r"(?<![\d])\d{10}(?![\d])")
PASSPORT_RE = re.compile(r"(?<![A-Za-z0-9])[A-Z]\s?\d{7}(?![A-Za-z0-9])")
SIM_RE = re.compile(rf"(?<![\d])\d{{4}}{_SEP}\d{{4}}{_SEP}\d{{4}}(?![\d])")

NISN_KEYWORDS = frozenset({"nisn", "dapodik"})
PASSPORT_KEYWORDS = frozenset({"paspor", "passport", "pasport"})
SIM_KEYWORDS = frozenset({"sim", "mengemudi"})

_MIN_BIRTH_YEAR = 1930
_MIN_AGE_AT_APPOINTMENT = 17
_MAX_YEAR = 2100


def validate_nip(value: str) -> bool:
    """True when ``value`` has the 18-digit NIP structure with a real birth date and a plausible appointment month."""
    d = digits_only(value)
    if len(d) != 18 or d[14] not in "12":
        return False
    year, month, day = int(d[0:4]), int(d[4:6]), int(d[6:8])
    tmt_year, tmt_month = int(d[8:12]), int(d[12:14])
    try:
        date(year, month, day)
    except ValueError:
        return False
    return year >= _MIN_BIRTH_YEAR and 1 <= tmt_month <= 12 and year + _MIN_AGE_AT_APPOINTMENT <= tmt_year <= _MAX_YEAR


def find_nip(text: str) -> list[PIIMatch]:
    return [
        PIIMatch("ID_NIP", m.start(), m.end(), m.group(), 0.95)
        for m in NIP_RE.finditer(text)
        if validate_nip(m.group())
    ]


def find_nisn(text: str) -> list[PIIMatch]:
    if not mentions_any(text, NISN_KEYWORDS):
        return []
    return [
        PIIMatch("ID_NISN", m.start(), m.end(), m.group(), 0.85)
        for m in NISN_RE.finditer(text)
        if has_keyword_near(text, m.start(), m.end(), NISN_KEYWORDS)
    ]


def find_passport(text: str) -> list[PIIMatch]:
    if not mentions_any(text, PASSPORT_KEYWORDS):
        return []
    return [
        PIIMatch("ID_PASSPORT", m.start(), m.end(), m.group(), 0.85)
        for m in PASSPORT_RE.finditer(text)
        if has_keyword_near(text, m.start(), m.end(), PASSPORT_KEYWORDS)
    ]


def find_sim(text: str) -> list[PIIMatch]:
    if not mentions_any(text, SIM_KEYWORDS):
        return []
    return [
        PIIMatch("ID_SIM", m.start(), m.end(), m.group(), 0.85)
        for m in SIM_RE.finditer(text)
        if has_keyword_near(text, m.start(), m.end(), SIM_KEYWORDS)
    ]
