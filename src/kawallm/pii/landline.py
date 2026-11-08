"""Indonesian landline numbers: area code + 6-8 digit subscriber number, e.g. ``(021) 5551234``.

Reported as ``ID_PHONE`` (``meta["landline"] = True``). To keep false positives low:

* ``(0xx) nnnnnnn`` with the area code in parentheses is distinctive enough to stand on its own.
* Every other form needs a *known* area code (``AREA_CODES``) and either an explicit separator / ``+62`` prefix
  (``021-5551234``, ``+62 21 5551234``) or a phone keyword nearby (``telp``, ``fax``, ...). Unseparated digits
  such as ``0215551234`` without a keyword are not reported.

``AREA_CODES`` covers major cities and regency capitals, not every code in the national plan; extend it by PR.
"""

from __future__ import annotations

import re

from .base import PIIMatch, digits_only, has_keyword_near, separator_segments

# fmt: off
AREA_CODES = frozenset(
    """
    021 022 024 031 061
    0251 0254 0260 0262 0263 0264 0265 0266 0267 0231 0232 0233 0234
    0271 0274 0275 0276 0281 0282 0283 0284 0285 0286 0287 0291 0292 0293 0294 0295 0296 0298
    0321 0322 0331 0332 0333 0334 0335 0341 0342 0343 0351 0352 0353 0354 0355 0356 0357 0358
    0361 0362 0370 0380
    0401 0411 0431 0435 0451
    0511 0536 0541 0542 0561
    0651 0711 0721 0736 0741 0751 0761 0771 0778
    0901 0911 0951 0967
    """.split()
)
# fmt: on

PAREN_RE = re.compile(r"\((?<![\d+(].)0[2-79]\d{1,3}\)[\s.\-]?\d{6,8}(?!\d)")
# No leading lookbehind: it defeats the regex engine's first-character scan, so the boundary is checked in find_landline.
LANDLINE_RE = re.compile(r"(?:\+62|62|0)[\s.\-]?[2-79]\d(?:[\s.\-]?\d){6,10}(?!\d)")

KEYWORDS = frozenset({"telp", "telepon", "tel", "fax", "faks", "phone", "telephone", "hotline"})


def split_landline(value: str) -> tuple[str, str] | None:
    """Split a number into ``(area code, subscriber)`` using ``AREA_CODES``; ``None`` when it does not fit."""
    d = digits_only(value)
    if d.startswith("62"):
        d = "0" + d[2:]
    if not d.startswith("0") or not 9 <= len(d) <= 12:
        return None
    for size in (4, 3):
        area, rest = d[:size], d[size:]
        if area in AREA_CODES and 6 <= len(rest) <= 8:
            return area, rest
    return None


def find_landline(text: str) -> list[PIIMatch]:
    if "0" not in text and "62" not in text:
        return []
    out = []
    for m in PAREN_RE.finditer(text) if "(" in text else ():
        area = re.match(r"\((0\d+)\)", m.group()).group(1)
        out.append(PIIMatch("ID_PHONE", m.start(), m.end(), m.group(), 0.9, {"landline": True, "area": area}))
    for m in LANDLINE_RE.finditer(text):
        if m.start() and (text[m.start() - 1].isdigit() or text[m.start() - 1] == "+"):
            continue  # starts inside a longer number
        for offset, part in separator_segments(m.group(), anchored_start=True):
            parts = split_landline(part)
            if parts is None:
                continue
            start = m.start() + offset
            end = start + len(part)
            explicit = part.startswith("+62") or any(ch in part for ch in " .-")
            if explicit or has_keyword_near(text, start, end, KEYWORDS):
                out.append(PIIMatch("ID_PHONE", start, end, part, 0.9, {"landline": True, "area": parts[0]}))
            break
    return out
