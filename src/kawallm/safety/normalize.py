"""Text normalisation used by both the dictionary compiler and the scanner.

Dictionary terms and input text go through the *same* function, so whatever
the normaliser does to "g4c0r" it also does to "gacor".
"""

from __future__ import annotations

import re
import unicodedata

_LEET = str.maketrans({"4": "a", "@": "a", "0": "o", "1": "i", "!": "i", "3": "e", "5": "s", "$": "s", "7": "t"})
# Starts directly with a leet character so the C regex engine skips pure alphabetic words.
_LEET_SPAN_RE = re.compile(r"[013457@$!][a-z0-9@$!]*")
# "s.l.o.t", "s l o t", "g-a-c-o-r": 3+ single chars joined by separators
# One spaced-out word uses ONE separator ("s.l.o.t", "s l o t"). Requiring the same separator throughout keeps a
# different one between words: "s.l.o.t g.4.c.0.r" -> "slot gacor", not "slotgacor".
_SPACED_RE = re.compile(r"(?<![a-z0-9])[a-z0-9@$]([.\-_*\s])(?:[a-z0-9@$]\1)+[a-z0-9@$](?![a-z0-9])")
_SPACED_HINT = re.compile(r"([.\-_*\s])[a-z0-9@$]\1[a-z0-9@$](?![a-z0-9])")
_REPEAT_RE = re.compile(r"([a-z])\1{2,}")
_WS_RE = re.compile(r"[^a-z0-9]+")
_ZW_RE = re.compile(r"[\u00ad\u200b-\u200f\u2060\ufeff]+")
_ASCII_WS_TABLE = str.maketrans({chr(i): " " for i in range(128) if not chr(i).isalnum()})


def _deleet_all(t: str) -> str:
    def _repl(m: re.Match) -> str:
        s = m.group()
        raw = s.rstrip("!")
        if not raw:
            return s
        i = m.start()
        while i > 0 and (t[i - 1].isalnum() or t[i - 1] in "@$"):
            i -= 1
        full = t[i : m.start()] + raw
        letters = sum(ch.isalpha() for ch in full)
        # Only de-leet tokens that are mostly words (keeps "10k", "4d", "2024" intact).
        if letters >= 2 and letters < len(full):
            return raw.translate(_LEET) + s[len(raw) :]
        return s

    return _LEET_SPAN_RE.sub(_repl, t)


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
    t = _deleet_all(t)
    t = _REPEAT_RE.sub(r"\1", t)
    if t.isascii():
        t = " ".join(t.translate(_ASCII_WS_TABLE).split())
    else:
        t = _WS_RE.sub(" ", t).strip()
    return f" {t} "
