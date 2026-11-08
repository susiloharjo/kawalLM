"""Shared types and helpers for PII detectors."""

from __future__ import annotations

import bisect
import functools
import re
from dataclasses import dataclass, field
from typing import Any

import ahocorasick

# Priority when two detections overlap: higher wins.
PRIORITY = {
    "ID_NIK": 100,
    "ID_NIP": 95,
    "ID_NPWP": 90,
    "ID_PASSPORT": 85,
    "ID_BPJS_KES": 80,
    "ID_BPJS_TK": 75,
    "ID_BANK_ACCOUNT": 70,
    "ID_NISN": 66,
    "ID_SIM": 65,
    "ID_PHONE": 60,
    "EMAIL": 55,
    "IP_ADDRESS": 45,
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


@functools.lru_cache(maxsize=32)
def _get_automaton(keywords: frozenset[str]) -> ahocorasick.Automaton:
    auto = ahocorasick.Automaton()
    for k in keywords:
        auto.add_word(k, k)
    auto.make_automaton()
    return auto


def mentions_any(text: str, keywords: frozenset[str], text_lower: str | None = None) -> bool:
    """Cheap pre-filter: True if any keyword occurs as a substring in ``text`` (case-insensitive)."""
    if not keywords:
        return False
    low = text_lower if text_lower is not None else text.lower()
    if len(keywords) <= 8:
        return any(k in low for k in keywords)
    auto = _get_automaton(keywords)
    for _ in auto.iter(low):
        return True
    return False


def has_keyword_near(text: str, start: int, end: int, keywords: frozenset[str], window_words: int = 5) -> str | None:
    """Return the first keyword found within ``window_words`` words around [start, end).

    Keywords are matched case-insensitively against whole alphabetic words.
    """
    before = _WORD_RE.findall(text[max(0, start - 100) : start].lower())[-window_words:]
    after = _WORD_RE.findall(text[end : end + 100].lower())[:window_words]
    for w in reversed(before):
        if w in keywords:
            return w
    for w in after:
        if w in keywords:
            return w
    return None


def resolve_overlaps(matches: list[PIIMatch]) -> list[PIIMatch]:
    """Keep non-overlapping matches, preferring higher priority then longer spans."""
    ordered = sorted(matches, key=lambda m: (-m.priority, -(m.end - m.start), m.start))
    # ``kept`` stays sorted by start and is non-overlapping, so only its two neighbours of a candidate can
    # conflict with it: O(n log n) instead of comparing every candidate with every kept span.
    starts: list[int] = []
    kept: list[PIIMatch] = []
    for m in ordered:
        i = bisect.bisect_left(starts, m.start)
        if i > 0 and kept[i - 1].end > m.start:
            continue
        if i < len(kept) and kept[i].start < m.end:
            continue
        starts.insert(i, m.start)
        kept.insert(i, m)
    return kept
