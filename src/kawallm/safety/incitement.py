"""SARA incitement patterns: violent verb + identity group.

Complements ``words/sara_id.json`` (slurs) with structural patterns like
"usir semua orang X" or "bantai kaum Y". Runs on normalised text.
"""

from __future__ import annotations

import re

from .jailbreak import Rule, _alts

_VERB = (
    r"(?:bunuh|bantai|basmi|habisi|musnahkan|usir|ganyang|bakar|serang|perangi|"
    r"hancurkan|binasakan|gantung|penggal|halalkan darah)"
)
_GROUP = (
    r"(?:cina|china|tionghoa|chinese|aseng|pribumi|jawa|sunda|batak|madura|bugis|dayak|"
    r"ambon|papua|minang|padang|arab|keturunan|kristen|katolik|nasrani|islam|muslim|"
    r"hindu|buddha|budha|konghucu|yahudi|syiah|ahmadiyah|kafir|ateis|lgbt|gay|minoritas|"
    r"pendatang|imigran)"
)

_GROUP_TRIGGERS = _alts(_GROUP)

INCITEMENT_RULES: tuple[Rule, ...] = (
    Rule(
        "SARA-ID-001",
        "SARA_HATE_SPEECH",
        re.compile(
            rf"\b{_VERB} (?:saja |aja |semua |seluruh |para )?(?:orang |kaum |etnis |suku |umat |ras |bangsa |para )?(?:{_GROUP})\b"
        ),
        1.0,
        "Hasutan kekerasan terhadap kelompok SARA",
        _GROUP_TRIGGERS,
    ),
    Rule(
        "SARA-ID-002",
        "SARA_HATE_SPEECH",
        re.compile(rf"\b{_GROUP} (?:harus|wajib|layak|pantas|halal) (?:\w+ ){{0,2}}(?:di)?{_VERB}(?:kan)?\b"),
        1.0,
        "Kelompok SARA 'harus dibunuh/diusir'",
        _GROUP_TRIGGERS,
    ),
    Rule(
        "SARA-ID-003",
        "SARA_HATE_SPEECH",
        re.compile(
            rf"\b(?:semua|seluruh) (?:orang |kaum |umat |etnis |suku )?{_GROUP} (?:itu )?(?:anjing|babi|monyet|sampah|binatang|iblis|setan|penyakit|parasit)\b"
        ),
        1.0,
        "Dehumanisasi kelompok SARA",
        ("anjing", "babi", "monyet", "sampah", "binatang", "iblis", "setan", "penyakit", "parasit"),
    ),
    Rule(
        "SARA-ID-004",
        "SARA_HATE_SPEECH",
        re.compile(
            r"\b(?:lelucon|lawakan|candaan|hinaan|ejekan|julukan|umpatan|makian|jokes?|insults?|slurs?)\b"
            r"(?: \w+){0,3} (?:rasis|rasialis|homofobik|homofobia|transfobik|sara|racist|homophobic)\b"
        ),
        1.0,
        "Permintaan konten rasis/homofobik",
        ("rasis", "rasialis", "homofobik", "homofobia", "transfobik", "sara", "racist", "homophobic"),
    ),
)
