"""Heuristic prompt-injection / jailbreak rules (Bahasa Indonesia + English).

Rules run on the *normalised* text from ``normalize()``: lowercase, no
punctuation, single spaces. Each rule has a weight; a category fires when the
sum of distinct rule weights reaches the threshold (default 1.0).

These are heuristics, not a classifier. They are meant for user-authored
content; do not run them on your own system prompt (it will often contain
phrases like "jangan bocorkan system prompt").
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    pattern: re.Pattern
    weight: float = 1.0
    description: str = ""


def _r(p: str) -> re.Pattern:
    return re.compile(p)


_IGNORE = r"(?:abaikan|lupakan|hiraukan|acuhkan|cuekin|tinggalkan|buang|ignore|disregard|forget)"
_INSTR = r"(?:instruksi|perintah|aturan|arahan|prompt|pesan|instructions?|rules?|prompts?|directions?)"
_PREV = r"(?:sebelumnya|sebelum ini|di atas|diatas|sistem|system|awal|previous|prior|above|earlier)"
_REVEAL = r"(?:bocorkan|tampilkan|tunjukkan|tunjukin|ulangi|tuliskan|sebutkan|cetak|kasih tahu|kasih tau|print|reveal|show|repeat|output|leak)"
_SYSPROMPT = (
    r"(?:system prompt|sistem prompt|prompt sistem|instruksi sistem|pesan sistem|"
    r"instruksi awal|prompt awal|initial prompt|hidden prompt|prompt rahasia|instruksi rahasia)"
)

JAILBREAK_RULES: tuple[Rule, ...] = (
    Rule(
        "JB-ID-001",
        "JAILBREAK",
        _r(rf"\b{_IGNORE}\b(?: \w+){{0,3}} {_INSTR}\b(?: \w+){{0,3}} {_PREV}\b"),
        1.0,
        "Abaikan/lupakan instruksi sebelumnya",
    ),
    Rule(
        "JB-EN-001",
        "JAILBREAK",
        _r(
            r"\b(?:ignore|disregard|forget|override)\b(?: \w+){0,2} (?:previous|prior|above|earlier|system) (?:\w+ ){0,2}(?:instructions?|prompts?|rules|directions)\b"
        ),
        1.0,
        "Ignore previous instructions (English word order)",
    ),
    Rule(
        "JB-ID-002",
        "JAILBREAK",
        _r(rf"\b{_IGNORE} (?:semua |seluruh |segala )?{_INSTR}\b"),
        0.6,
        "Abaikan semua instruksi (tanpa penanda 'sebelumnya')",
    ),
    Rule(
        "JB-ID-003",
        "JAILBREAK",
        _r(rf"\b{_REVEAL}\b(?: \w+){{0,4}} {_SYSPROMPT}\b"),
        1.0,
        "Bocorkan/tampilkan system prompt",
    ),
    Rule(
        "JB-ID-004",
        "JAILBREAK",
        _r(
            r"\b(?:mulai sekarang|dari sekarang|sekarang|mulai saat ini|from now on|now) "
            r"(?:kamu|kau|anda|lu|lo|elu|you) (?:adalah|jadi|menjadi|berperan sebagai|bertindak sebagai|are|will be|act as) "
            r"(?:\w+ ){0,3}(?:dan|dan ai|do anything now|jahat|tanpa batas|tanpa batasan|tanpa aturan|tanpa sensor|tanpa filter|"
            r"evil|unrestricted|unfiltered|uncensored|jailbroken|developer mode|mode pengembang)\b"
        ),
        1.0,
        "Mulai sekarang kamu adalah DAN / karakter jahat",
    ),
    Rule(
        "JB-ID-005",
        "JAILBREAK",
        _r(
            r"\b(?:mode pengembang|mode developer|developer mode|god mode|mode dewa|dan mode|mode dan|jailbreak mode|mode jailbreak)\b"
        ),
        0.6,
        "Aktivasi mode khusus",
    ),
    Rule(
        "JB-ID-006",
        "JAILBREAK",
        _r(
            r"\b(?:tanpa|tidak ada|tak ada|no|without) (?:sensor|filter|batasan|aturan|etika|moral|restrictions?|censorship|filters?|guidelines?)\b"
        ),
        0.4,
        "Minta respons tanpa sensor/filter",
    ),
    Rule(
        "JB-ID-007",
        "JAILBREAK",
        _r(
            r"\b(?:pura pura|berpura pura|bayangkan|anggap|pretend|imagine|roleplay)\b(?: \w+){0,6} "
            r"(?:tidak punya|tidak memiliki|tanpa|bebas dari|no|without) (?:aturan|batasan|filter|sensor|rules|restrictions|limits)\b"
        ),
        1.0,
        "Roleplay untuk melepas batasan",
    ),
    Rule(
        "JB-ID-008",
        "JAILBREAK",
        _r(
            r"\b(?:kamu|anda|you) (?:bukan lagi|tidak lagi|no longer|are not) (?:ai|asisten|assistant|model bahasa|language model|chatgpt|claude)\b"
        ),
        0.6,
        "Menyangkal identitas asisten",
    ),
    Rule(
        "JB-ID-009",
        "JAILBREAK",
        _r(
            r"\b(?:override|timpa|ganti|ubah|reset) (?:\w+ ){0,2}(?:system prompt|instruksi sistem|prompt sistem|aturan sistem|safety|guardrail|kebijakan keamanan)\b"
        ),
        1.0,
        "Override instruksi sistem / guardrail",
    ),
    Rule(
        "JB-ID-010",
        "JAILBREAK",
        _r(r"\b(?:jailbreak|prompt injection|injeksi prompt)\b"),
        0.4,
        "Menyebut jailbreak secara eksplisit",
    ),
)
