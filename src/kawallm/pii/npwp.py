"""NPWP detection (15-digit legacy and 16-digit format).

Legacy NPWP: XX.XXX.XXX.X-XXX.XXX — the 9th digit is a Luhn check digit over
the first 8 digits (same rule as python-stdnum ``stdnum.id.npwp``).

16-digit NPWP (since PMK 112/2022): individuals use their NIK; entities use
"0" + the legacy 15 digits. A 16-digit NIK-shaped number is reported by the NIK
detector, so here we only handle the "0" + legacy form.

To avoid colliding with 15-digit bank accounts (e.g. BRI), *unformatted*
numbers are only reported when an NPWP keyword is nearby. The dotted format is
specific enough to stand on its own.
"""

from __future__ import annotations

import re

from .base import PIIMatch, digits_only, has_keyword_near, mentions_any

NPWP_FORMATTED_RE = re.compile(r"\d(?<!\d.)\d{1,2}\.\d{3}\.\d{3}\.\d-\d{3}\.\d{3}(?!\d)")
NPWP_PLAIN_RE = re.compile(r"\d(?<![\d.\-].)(?:\d{14}|(?<=0)\d{15})(?!\d)")

NPWP_KEYWORDS = frozenset({"npwp", "pajak", "wajib", "djp", "nitku", "taxpayer", "tin"})


def luhn_valid(number: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(number)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def validate_npwp(value: str) -> bool:
    d = digits_only(value)
    if len(d) == 16:
        if d[0] != "0":
            return False  # NIK-based NPWP is validated by the NIK detector
        d = d[1:]
    if len(d) != 15:
        return False
    return luhn_valid(d[:9])


def find_npwp(text: str, text_lower: str | None = None) -> list[PIIMatch]:
    out = []
    if "." in text and "-" in text:
        for m in NPWP_FORMATTED_RE.finditer(text):
            if validate_npwp(m.group()):
                out.append(PIIMatch("ID_NPWP", m.start(), m.end(), m.group(), 1.0))
    if mentions_any(text, NPWP_KEYWORDS, text_lower=text_lower):
        for m in NPWP_PLAIN_RE.finditer(text):
            if validate_npwp(m.group()) and has_keyword_near(text, m.start(), m.end(), NPWP_KEYWORDS):
                out.append(PIIMatch("ID_NPWP", m.start(), m.end(), m.group(), 0.9))
    return out
