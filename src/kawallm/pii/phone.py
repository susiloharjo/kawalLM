"""Indonesian mobile number detection with operator-prefix validation (landlines: see ``landline.py``).

Accepts +62 8xx, 62 8xx and 08xx forms with optional spaces / dots / dashes.
Normalised local length (starting with 08) must be 10–13 digits and the 4-digit
prefix must belong to a known operator.
"""

from __future__ import annotations

import re

from .base import PIIMatch, digits_only
from .landline import find_landline

PHONE_RE = re.compile(r"(?<![\d+])(?:\+62|62|0)[\s.\-]?8\d{1,2}(?:[\s.\-]?\d){6,10}(?![\d])")

OPERATOR_PREFIXES: dict[str, str] = {}
for _op, _prefixes in {
    "Telkomsel": ["0811", "0812", "0813", "0821", "0822", "0823", "0851", "0852", "0853"],
    "Indosat": ["0814", "0815", "0816", "0855", "0856", "0857", "0858"],
    "Tri": ["0895", "0896", "0897", "0898", "0899"],
    "XL": ["0817", "0818", "0819", "0859", "0877", "0878"],
    "Axis": ["0831", "0832", "0833", "0838"],
    "Smartfren": ["0881", "0882", "0883", "0884", "0885", "0886", "0887", "0888", "0889"],
}.items():
    for _p in _prefixes:
        OPERATOR_PREFIXES[_p] = _op


def normalize_phone(value: str) -> str:
    d = digits_only(value)
    if d.startswith("62"):
        d = "0" + d[2:]
    return d


def phone_operator(value: str) -> str | None:
    d = normalize_phone(value)
    if not (10 <= len(d) <= 13):
        return None
    return OPERATOR_PREFIXES.get(d[:4])


def find_phone(text: str) -> list[PIIMatch]:
    out = []
    for m in PHONE_RE.finditer(text):
        op = phone_operator(m.group())
        if op:
            out.append(PIIMatch("ID_PHONE", m.start(), m.end(), m.group(), 1.0, {"operator": op}))
    return out + find_landline(text)
