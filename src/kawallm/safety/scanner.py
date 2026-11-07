"""Aho-Corasick dictionary scanner + regex rules.

All dictionaries under ``safety/words/*.json`` are compiled into a single
automaton (pyahocorasick) once, so scan time is O(n + matches) regardless of
dictionary size.

Dictionary format::

    {
      "category": "JUDOL_PINJOL",
      "default_weight": 1.0,
      "terms": [{"term": "slot gacor", "weight": 1.0}, {"term": "zeus", "weight": 0.5}]
    }

A term may set ``"prefix": true`` to also match inflected forms
(``anjing`` → ``anjingnya``). Otherwise matching is whole-word on the
normalised text.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

import ahocorasick

from .incitement import INCITEMENT_RULES
from .jailbreak import JAILBREAK_RULES, Rule
from .normalize import normalize

CATEGORIES = ("TOXIC_SLANG", "JUDOL_PINJOL", "SARA_HATE_SPEECH", "JAILBREAK")

# Words that mark text as discussing/reporting a topic rather than promoting it (normalised, single tokens).
EDUCATIONAL_WORDS = frozenset(
    "jelaskan bahaya dampak edukasi mencegah cegah hindari waspada laporkan melaporkan mengapa kenapa penelitian".split()
)

CATEGORY_LABELS = {
    "TOXIC_SLANG": "kata kasar / umpatan",
    "JUDOL_PINJOL": "promosi judi online / pinjol ilegal",
    "SARA_HATE_SPEECH": "ujaran kebencian SARA",
    "JAILBREAK": "upaya prompt injection / jailbreak",
}


@dataclass
class Hit:
    category: str
    term: str
    weight: float
    source: str  # dictionary file name or rule id


@dataclass
class SafetyResult:
    safe: bool
    violations: dict[str, float] = field(default_factory=dict)  # category -> score
    hits: list[Hit] = field(default_factory=list)
    flagged: dict[str, float] = field(default_factory=dict)  # matched but below threshold / not blocking

    @property
    def message(self) -> str:
        """Human-readable Indonesian message, e.g. for an HTTP error body."""
        if self.safe:
            return ""
        labels = ", ".join(f"{CATEGORY_LABELS.get(c, c)} ({c})" for c in self.violations)
        return f"Konten terdeteksi memuat {labels}."

    @property
    def reason(self) -> str:
        if self.safe:
            return ""
        parts = []
        for cat in self.violations:
            terms = sorted({h.term for h in self.hits if h.category == cat})[:3]
            parts.append(f"{cat} ({', '.join(terms)})")
        return "; ".join(parts)


def _builtin_dictionaries() -> list[tuple[str, dict]]:
    out = []
    folder = resources.files("kawallm.safety").joinpath("words")
    for entry in sorted(folder.iterdir(), key=lambda p: p.name):
        if entry.name.endswith(".json"):
            out.append((entry.name, json.loads(entry.read_text(encoding="utf-8"))))
    return out


class SafetyScanner:
    def __init__(
        self,
        extra_dictionaries: Iterable[str | Path] = (),
        extra_rules: Iterable[Rule] = (),
        threshold: float = 1.0,
        block_categories: Iterable[str] = ("JUDOL_PINJOL", "SARA_HATE_SPEECH", "JAILBREAK"),
        enabled_categories: Iterable[str] = CATEGORIES,
    ) -> None:
        self.threshold = threshold
        self.block_categories = frozenset(block_categories)
        self.enabled = frozenset(enabled_categories)
        self.rules: tuple[Rule, ...] = tuple(
            r for r in (*JAILBREAK_RULES, *INCITEMENT_RULES, *extra_rules) if r.category in self.enabled
        )
        dicts = _builtin_dictionaries()
        for p in extra_dictionaries:
            p = Path(p)
            dicts.append((p.name, json.loads(p.read_text(encoding="utf-8"))))
        self._automaton = ahocorasick.Automaton()
        self.term_count = 0
        self._has_automaton = False
        for source, d in dicts:
            cat = d["category"]
            if cat not in self.enabled:
                continue
            default_w = float(d.get("default_weight", 1.0))
            for t in d["terms"]:
                if isinstance(t, str):
                    t = {"term": t}
                norm = normalize(t["term"]).strip()
                if not norm:
                    continue
                payload = (cat, t["term"], float(t.get("weight", default_w)), source)
                # Multi-word terms are also stored without spaces: "s l o t g a c o r" normalises to
                # "slotgacor" because a fully spaced-out text has no visible word boundary.
                forms = {norm, norm.replace(" ", "")}
                for form in forms:
                    key = f" {form}" if t.get("prefix") else f" {form} "
                    existing = self._automaton.get(key, None)
                    if existing is None:
                        self._automaton.add_word(key, ([payload], []))
                        self.term_count += 1
                        self._has_automaton = True
                    else:
                        existing[0].append(payload)

        # Index rule trigger words in the same Aho-Corasick automaton so regex rules
        # only run when at least one of their anchor words is present in the text.
        self._always_rules: list[Rule] = []
        for idx, rule in enumerate(self.rules):
            if not rule.triggers:
                self._always_rules.append(rule)
                continue
            for trig in rule.triggers:
                key = f" {trig} "
                existing = self._automaton.get(key, None)
                if existing is None:
                    self._automaton.add_word(key, ([], [idx]))
                    self._has_automaton = True
                elif idx not in existing[1]:
                    existing[1].append(idx)

        if self._has_automaton:
            self._automaton.make_automaton()

    def scan(self, text: str) -> SafetyResult:
        if not text or not isinstance(text, str):
            return SafetyResult(safe=True)
        norm = normalize(text)
        hits: list[Hit] = []
        triggered: set[int] = set()
        if self._has_automaton:
            raw_hits: list[tuple[str, str, float, str]] = []
            for _, (payloads, rule_idxs) in self._automaton.iter(norm):
                if payloads:
                    raw_hits.extend(payloads)
                if rule_idxs:
                    triggered.update(rule_idxs)
            if raw_hits:
                # Educational / reporting context: ambiguous words (weight < 1) count half, so "jelaskan bahaya
                # judi online dan pinjol" passes while strong promotional phrases (weight >= 1) still block.
                educational = any(w < 1.0 for _, _, w, _ in raw_hits) and any(
                    f" {w} " in norm for w in EDUCATIONAL_WORDS
                )
                for cat, term, w, src in raw_hits:
                    hits.append(Hit(cat, term, w * 0.5 if educational and w < 1.0 else w, src))
        for idx in sorted(triggered):
            rule = self.rules[idx]
            if rule.pattern.search(norm):
                hits.append(Hit(rule.category, rule.description or rule.id, rule.weight, rule.id))
        for rule in self._always_rules:
            if rule.pattern.search(norm):
                hits.append(Hit(rule.category, rule.description or rule.id, rule.weight, rule.id))

        # Score = sum of the best weight per distinct term, per category.
        best: dict[tuple[str, str], float] = {}
        for h in hits:
            k = (h.category, h.term)
            best[k] = max(best.get(k, 0.0), h.weight)
        scores: dict[str, float] = {}
        for (cat, _), w in best.items():
            scores[cat] = scores.get(cat, 0.0) + w

        violations = {c: round(s, 3) for c, s in scores.items() if s >= self.threshold and c in self.block_categories}
        flagged = {c: round(s, 3) for c, s in scores.items() if c not in violations}
        return SafetyResult(safe=not violations, violations=violations, hits=hits, flagged=flagged)
