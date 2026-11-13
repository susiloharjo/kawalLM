"""Indonesian vehicle plate (TNKB) detection, e.g. ``B 1234 ABC``.

Only uppercase plates with a known regional prefix and a 1–3 letter suffix are
reported, to keep false positives on ordinary text low.
"""

from __future__ import annotations

import re

from .base import PIIMatch

REGION_CODES = frozenset(
    """
    A B D E F G H K L M N P R S T W Z
    AA AB AD AE AG
    BA BB BD BE BG BH BK BL BM BN BP
    DA DB DC DD DE DG DH DK DL DM DN DR DT
    EA EB ED
    KB KH KT KU
    PA PB PG PY
    """.split()
)

# A label that names something else (a class, a block, a bus route): "Kelas A 1234 BC" is not a plate.
_NOT_A_PLATE_AFTER = re.compile(
    r"(?<![a-z])(?:kelas|blok|lantai|rute|tipe|type|model|seri|pasal|ruang|gedung|class|floor|room|block|route|series)\s*$"
)

PLATE_RE = re.compile(r"([A-Z](?<![A-Za-z0-9].)[A-Z]?)\s?(\d{1,4})\s?([A-Z]{1,3})(?![A-Za-z0-9])")


def find_plate(text: str) -> list[PIIMatch]:
    out = []
    for m in PLATE_RE.finditer(text):
        if m.group(1) in REGION_CODES and not _NOT_A_PLATE_AFTER.search(
            text[max(0, m.start() - 10) : m.start()].lower()
        ):
            out.append(PIIMatch("ID_PLATE", m.start(), m.end(), m.group(), 0.8))
    return out
