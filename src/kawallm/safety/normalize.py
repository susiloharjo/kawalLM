"""Text normalisation used by both the dictionary compiler and the scanner.

Dictionary terms and input text go through the *same* function, so whatever
the normaliser does to "g4c0r" it also does to "gacor".
"""

from __future__ import annotations

import re
import unicodedata

import ahocorasick

_LEET = str.maketrans({"4": "a", "@": "a", "0": "o", "1": "i", "!": "i", "3": "e", "5": "s", "$": "s", "7": "t"})
# Starts directly with a leet character so the C regex engine skips pure alphabetic words.
_LEET_SPAN_RE = re.compile(r"[013457@$!][a-z0-9@$!]*")

# "s.l.o.t", "s l o t", "g-a.c_o-r": single chars joined by separators.
# Mixed punctuation separators [.\-_*] are allowed within a word without swallowing inter-word spaces.
# Pure spaces are also allowed ("s l o t").
_SPACED_RE = re.compile(r"(?<![a-z0-9])[a-z0-9@$](?:(?:[.\-_*][a-z0-9@$]){2,}|(?:\s[a-z0-9@$]){2,})(?![a-z0-9])")
_SPACED_HINT = re.compile(r"[.\-_*][a-z0-9@$][.\-_*]|\s[a-z0-9@$]\s[a-z0-9@$](?![a-z0-9])")

_REPEAT_AUTOMATON = ahocorasick.Automaton()
for _c in "abcdefghijklmnopqrstuvwxyz":
    _REPEAT_AUTOMATON.add_word(_c * 3, _c)
_REPEAT_AUTOMATON.make_automaton()

_REPEAT_RE = re.compile(r"([a-z])\1{2,}")

_WS_RE = re.compile(r"[^a-z0-9]+")
# Invisible characters including zero-width and Unicode bidirectional formatting characters.
_ZW_RE = re.compile(r"[\u00ad\u200b-\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]+")
_ASCII_WS_TABLE = str.maketrans({chr(i): " " for i in range(128) if not chr(i).isalnum()})

# Cyrillic and Greek homoglyphs commonly used for Latin letter evasion.
_HOMOGLYPH_TABLE = str.maketrans(
    {
        # Cyrillic lowercase
        "и": "i",
        "һ": "h",
        "ԁ": "d",
        "ԝ": "w",
        "ɡ": "g",
        "ո": "n",
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "х": "x",
        "і": "i",
        "ѕ": "s",
        "ј": "j",
        "к": "k",
        "м": "m",
        "т": "t",
        "в": "b",
        "н": "h",
        # Cyrillic uppercase
        "А": "a",
        "В": "b",
        "Е": "e",
        "К": "k",
        "М": "m",
        "Н": "h",
        "О": "o",
        "Р": "p",
        "С": "c",
        "Т": "t",
        "У": "y",
        "Х": "x",
        "І": "i",
        "Ј": "j",
        "Ѕ": "s",
        # Greek lowercase
        "α": "a",
        "β": "b",
        "ε": "e",
        "ι": "i",
        "κ": "k",
        "ν": "v",
        "ο": "o",
        "ρ": "p",
        "τ": "t",
        "υ": "y",
        "χ": "x",
        # Greek uppercase
        "Α": "a",
        "Β": "b",
        "Ε": "e",
        "Ζ": "z",
        "Η": "h",
        "Ι": "i",
        "Κ": "k",
        "Μ": "m",
        "Ν": "n",
        "Ο": "o",
        "Ρ": "p",
        "Τ": "t",
        "Υ": "y",
        "Χ": "x",
    }
)

# Dictionary terms that genuinely contain digits and must not have their tail digits split.
_KEEP_TERMS = frozenset({"slot88"})
_TAIL_RE = re.compile(r"\b([a-z]{4,})(\d+)\b")


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
        # Do not convert trailing twin digits (e.g. 77, 88, 99) or 8x/9x number suffixes into leet letters
        m_twin = re.search(r"(?:(\d)\1+|[89]\d*)$", raw)
        trailing = ""
        to_deleet = raw
        if m_twin:
            trailing = m_twin.group()
            to_deleet = raw[: -len(trailing)]

        letters = sum(ch.isalpha() for ch in full)
        # Only de-leet tokens that are mostly words (keeps "10k", "4d", "2024" intact).
        if letters >= 2 and letters < len(full):
            return to_deleet.translate(_LEET) + trailing + s[len(raw) :]
        return s

    return _LEET_SPAN_RE.sub(_repl, t)


def _split_tail_digits(t: str) -> str:
    def _repl(m: re.Match) -> str:
        w = m.group()
        if w in _KEEP_TERMS:
            return w
        return f"{m.group(1)} {m.group(2)}"

    return _TAIL_RE.sub(_repl, t)


def _squash_repeats(t: str) -> str:
    for _ in _REPEAT_AUTOMATON.iter(t):
        return _REPEAT_RE.sub(r"\1", t)
    return t


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
        t = t.translate(_HOMOGLYPH_TABLE)
        t = unicodedata.normalize("NFKD", t)
        t = "".join(ch for ch in t if not unicodedata.combining(ch)).lower()
    if _SPACED_HINT.search(t):
        t = _SPACED_RE.sub(lambda m: _WS_RE.sub("", m.group()), t)
    t = _deleet_all(t)
    t = _split_tail_digits(t)
    t = _squash_repeats(t)
    if t.isascii():
        t = " ".join(t.translate(_ASCII_WS_TABLE).split())
    else:
        t = _WS_RE.sub(" ", t).strip()
    return f" {t} "
