"""Proximity-based Indonesian bank account detection.

A digit run is reported as an account number only when a bank name (or a
generic "rekening" keyword) appears within ``window`` words AND its length fits
that bank's known account length. Lengths are typical public formats; extend
``BANK_ACCOUNT_LENGTHS`` via PR if your bank is missing.
"""

from __future__ import annotations

import re

from .base import PIIMatch, digits_only

BANK_ACCOUNT_LENGTHS: dict[str, frozenset[int]] = {
    "bca": frozenset({10}),
    "mandiri": frozenset({13}),
    "bri": frozenset({15}),
    "bni": frozenset({10}),
    "bsi": frozenset({10}),
    "btn": frozenset({16}),
    "cimb": frozenset({12, 13, 14}),
    "niaga": frozenset({12, 13, 14}),
    "danamon": frozenset({10}),
    "permata": frozenset({10}),
    "panin": frozenset({10}),
    "ocbc": frozenset({12}),
    "maybank": frozenset({10}),
    "jago": frozenset({12}),
    "seabank": frozenset({12}),
    "blu": frozenset({12}),
    "mega": frozenset({15}),
    "btpn": frozenset({11, 12}),
    "jenius": frozenset({11, 12}),
}
GENERIC_KEYWORDS = frozenset({"rekening", "rek", "norek", "account", "acc", "transfer", "tf"})
GENERIC_LENGTHS = frozenset(range(10, 17))

# Digit groups separated by single space/dot/dash, 9–19 digits total.
ACCOUNT_RE = re.compile(r"(?<![\d.\-])\d(?:[\s.\-]?\d){8,18}(?![\d])")
_WORD_RE = re.compile(r"[A-Za-z]+")


def find_bank_account(text: str, window: int = 5) -> list[PIIMatch]:
    out = []
    for m in ACCOUNT_RE.finditer(text):
        n = len(digits_only(m.group()))
        before = [w.lower() for w in _WORD_RE.findall(text[max(0, m.start() - 120) : m.start()])]
        after = [w.lower() for w in _WORD_RE.findall(text[m.end() : m.end() + 120])]
        nearby = list(reversed(before[-window:])) + after[:window]
        bank = next((w for w in nearby if w in BANK_ACCOUNT_LENGTHS), None)
        if bank is not None:
            if n in BANK_ACCOUNT_LENGTHS[bank]:
                out.append(PIIMatch("ID_BANK_ACCOUNT", m.start(), m.end(), m.group(), 0.95, {"bank": bank}))
            continue
        if any(w in GENERIC_KEYWORDS for w in nearby) and n in GENERIC_LENGTHS:
            out.append(PIIMatch("ID_BANK_ACCOUNT", m.start(), m.end(), m.group(), 0.7, {}))
    return out
