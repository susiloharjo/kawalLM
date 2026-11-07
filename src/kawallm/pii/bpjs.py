"""BPJS Kesehatan (13 digits) and BPJS Ketenagakerjaan / KPJ (11 digits).

BPJS Kesehatan card numbers start with "000"; we accept that prefix on its own,
or any 13 digits with a BPJS keyword nearby. BPJS Ketenagakerjaan numbers have
no distinctive prefix, so they always require a keyword.
"""

from __future__ import annotations

import re

from .base import PIIMatch, digits_only, has_keyword_near, mentions_any

BPJS_KES_RE = re.compile(r"\d(?<!\d.)\d{3}[\s.\-]?\d{4}[\s.\-]?\d{5}(?!\d)")
BPJS_TK_RE = re.compile(r"\d(?<!\d.)\d{10}(?!\d)")

KES_KEYWORDS = frozenset({"bpjs", "kesehatan", "jkn", "kis", "faskes"})
TK_KEYWORDS = frozenset({"bpjs", "ketenagakerjaan", "bpjstk", "kpj", "jamsostek", "jht"})


def find_bpjs(text: str) -> list[PIIMatch]:
    out = []
    if "000" in text or mentions_any(text, KES_KEYWORDS):
        for m in BPJS_KES_RE.finditer(text):
            d = digits_only(m.group())
            if len(d) != 13:
                continue
            if d.startswith("000") or has_keyword_near(text, m.start(), m.end(), KES_KEYWORDS):
                out.append(PIIMatch("ID_BPJS_KES", m.start(), m.end(), m.group(), 0.9))
    if mentions_any(text, TK_KEYWORDS):
        for m in BPJS_TK_RE.finditer(text):
            if has_keyword_near(text, m.start(), m.end(), TK_KEYWORDS):
                out.append(PIIMatch("ID_BPJS_TK", m.start(), m.end(), m.group(), 0.85))
    return out
