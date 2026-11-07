"""Text normalisation used by both the dictionary compiler and the scanner.

Dictionary terms and input text go through the *same* function, so whatever
the normaliser does to "g4c0r" it also does to "gacor".
"""

from __future__ import annotations

import re
import unicodedata

_LEET = str.maketrans({"4": "a", "@": "a", "0": "o", "1": "i", "!": "i", "3": "e", "5": "s", "$": "s", "7": "t"})
# Tokens that contain at least one leet character, e.g. g4c0r, m4xw!n, $lot
# ("!" only counts when it sits between other token characters).
_TOKEN_RE = re.compile(r"(?<![a-z0-9@$])(?=[a-z]*[0-9@$!])[a-z0-9@$]+(?:!+[a-z0-9@$]+)*")
# "s.l.o.t", "s l o t", "g-a-c-o-r": 3+ single chars joined by separators
# One spaced-out word uses ONE separator ("s.l.o.t", "s l o t"). Requiring the same separator throughout keeps a
# different one between words: "s.l.o.t g.4.c.0.r" -> "slot gacor", not "slotgacor".
_SPACED_RE = re.compile(r"(?<![a-z0-9])[a-z0-9@$]([.\-_*\s])(?:[a-z0-9@$]\1)+[a-z0-9@$](?![a-z0-9])")
_SPACED_HINT = re.compile(r"(?<![a-z0-9])[a-z0-9@$]([.\-_*\s])[a-z0-9@$]\1[a-z0-9@$](?![a-z0-9])")
_REPEAT_RE = re.compile(r"([a-z])\1{2,}")
_WS_RE = re.compile(r"[^a-z0-9]+")
_ZW_RE = re.compile(r"[\u00ad\u200b-\u200f\u2060\ufeff]+")


def _deleet_token(m: re.Match) -> str:
    tok = m.group()
    letters = sum(ch.isalpha() for ch in tok)
    # Only de-leet tokens that are mostly words (keeps "10k", "4d", "2024" intact).
    if letters >= 2 and letters < len(tok):
        return tok.translate(_LEET)
    return tok


def normalize(text: str) -> str:
    """Lowercase, strip accents, undo spacing tricks and leetspeak, squash repeats.

    Output contains only ``[a-z0-9]`` words separated by single spaces, padded
    with a leading/trailing space so word-boundary matching is a plain substring
    search for `` term ``.
    """
    if text.isascii():
        t = text.lower()
    else:
        t = _ZW_RE.sub("", text)
        t = unicodedata.normalize("NFKD", t)
        t = "".join(ch for ch in t if not unicodedata.combining(ch)).lower()
    if _SPACED_HINT.search(t):
        t = _SPACED_RE.sub(lambda m: _WS_RE.sub("", m.group()), t)
    t = _TOKEN_RE.sub(_deleet_token, t)
    t = _REPEAT_RE.sub(r"\1", t)
    t = _WS_RE.sub(" ", t).strip()
    return f" {t} "
