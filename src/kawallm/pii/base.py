"""Shared types and helpers for PII detectors."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# Priority when two detections overlap: higher wins.
PRIORITY = {
    "ID_NIK": 100,
    "ID_NPWP": 90,
    "ID_BPJS_KES": 80,
    "ID_BPJS_TK": 75,
    "ID_BANK_ACCOUNT": 70,
    "ID_PHONE": 60,
    "EMAIL": 55,
    "ID_PLATE": 40,
}

_WORD_RE = re.compile(r"[A-Za-z]+")


@dataclass(frozen=True)
class PIIMatch:
    """A detected PII span in the original text."""

    entity: str
    start: int
    end: int
    text: str
    score: float = 1.0
    meta: dict[str, Any] = field(default_factory=dict, compare=False, hash=False)

    @property
    def priority(self) -> int:
        return PRIORITY.get(self.entity, 0)


def digits_only(s: str) -> str:
    return "".join(ch for ch in s if ch.isdigit())


def has_keyword_near(text: str, start: int, end: int, keywords: frozenset[str], window_words: int = 5) -> str | None:
    """Return the first keyword found within ``window_words`` words around [start, end).

    Keywords are matched case-insensitively against whole alphabetic words.
    """
    before = _WORD_RE.findall(text[max(0, start - 120) : start])[-window_words:]
    after = _WORD_RE.findall(text[end : end + 120])[:window_words]
    for w in reversed(before):
        if w.lower() in keywords:
            return w.lower()
    for w in after:
        if w.lower() in keywords:
            return w.lower()
    return None


def resolve_overlaps(matches: list[PIIMatch]) -> list[PIIMatch]:
    """Keep non-overlapping matches, preferring higher priority then longer spans."""
    ordered = sorted(matches, key=lambda m: (-m.priority, -(m.end - m.start), m.start))
    kept: list[PIIMatch] = []
    for m in ordered:
        if all(m.end <= k.start or m.start >= k.end for k in kept):
            kept.append(m)
    return sorted(kept, key=lambda m: m.start)
