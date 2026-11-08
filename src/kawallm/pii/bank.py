"""Proximity-based Indonesian bank account detection.

A digit run is reported as an account number only when a bank name (or a
generic "rekening" keyword) appears within ``window`` words AND its length fits
that bank's known account length. Lengths are typical public formats; extend
``BANK_ACCOUNT_LENGTHS`` via PR if your bank is missing.
"""

from __future__ import annotations

import re

from .base import PIIMatch, digits_only, mentions_any

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
    "bca digital": frozenset({12}),
    "muamalat": frozenset({10}),
    "bjb": frozenset({13}),
    "bank dki": frozenset({11, 12}),
    "bank jatim": frozenset({10}),
}
BANK_SPECS = BANK_ACCOUNT_LENGTHS
GENERIC_KEYWORDS = frozenset({"rekening", "rek", "norek", "account", "acc", "transfer", "tf"})
GENERIC_LENGTHS = frozenset(range(10, 17))
_ALL_KEYWORDS = frozenset(w for k in BANK_ACCOUNT_LENGTHS for w in k.split()) | GENERIC_KEYWORDS

# Digit groups separated by single space/dot/dash, 9–19 digits total.
ACCOUNT_RE = re.compile(r"\d(?<![\d.\-].)(?:[\s.\-]?\d){8,18}(?!\d)")
_WORD_RE = re.compile(r"[A-Za-z]+")


def find_bank_account(text: str, window: int = 5, text_lower: str | None = None) -> list[PIIMatch]:
    low = text_lower if text_lower is not None else text.lower()
    if not mentions_any(text, _ALL_KEYWORDS, text_lower=low):
        return []
    out = []
    for m in ACCOUNT_RE.finditer(text):
        raw = m.group()
        # Reject candidates that mix different separators (e.g. "2026-11-07 20.45").
        if len({ch for ch in raw if not ch.isdigit()}) > 1:
            continue
        n = len(digits_only(raw))
        if n not in GENERIC_LENGTHS:
            continue
        span_low = low[max(0, m.start() - 120) : m.end() + 120]
        if not mentions_any(span_low, _ALL_KEYWORDS, text_lower=span_low):
            continue
        before = _WORD_RE.findall(low[max(0, m.start() - 120) : m.start()])[-window:]
        after = _WORD_RE.findall(low[m.end() : m.end() + 120])[:window]
        nearby: list[str] = []
        n_b = len(before)
        for i in range(n_b - 1, -1, -1):
            if i > 0:
                nearby.append(f"{before[i - 1]} {before[i]}")
            nearby.append(before[i])
        n_a = len(after)
        for i in range(n_a):
            if i + 1 < n_a:
                nearby.append(f"{after[i]} {after[i + 1]}")
            nearby.append(after[i])
        bank = next((w for w in nearby if w in BANK_ACCOUNT_LENGTHS), None)
        if bank is not None:
            if n in BANK_ACCOUNT_LENGTHS[bank]:
                out.append(PIIMatch("ID_BANK_ACCOUNT", m.start(), m.end(), raw, 0.95, {"bank": bank}))
            continue
        if any(w in GENERIC_KEYWORDS for w in nearby):
            out.append(PIIMatch("ID_BANK_ACCOUNT", m.start(), m.end(), raw, 0.7, {}))
    return out
