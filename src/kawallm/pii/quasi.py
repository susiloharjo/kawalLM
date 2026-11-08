"""Quasi-identifiers: birth date, age, postal code, street address and GPS coordinates.

None of these identifies a person alone, but a few of them together can, so they belong to the opt-in ``extended``
profile (see ``kawallm.pii.PROFILES``). Every detector needs a label or a structural marker, to keep false positives
low: a date is only a birth date next to "tanggal lahir"/"TTL", a number is only an age after "umur"/"usia", and an
address needs a street marker (``Jl.``, ``Gang``...) plus a house number, RT/RW or an administrative area.

Each match carries the parsed parts in ``meta``, which the ``generalize`` mask mode uses to lower the precision
instead of replacing the value (a birth date becomes the year, an address becomes its area).
"""

from __future__ import annotations

import re
from datetime import date

from .base import PIIMatch, mentions_any

_MONTHS = {
    "januari": 1, "jan": 1, "january": 1,
    "februari": 2, "feb": 2, "february": 2, "pebruari": 2,
    "maret": 3, "mar": 3, "march": 3,
    "april": 4, "apr": 4,
    "mei": 5, "may": 5,
    "juni": 6, "jun": 6, "june": 6,
    "juli": 7, "jul": 7, "july": 7,
    "agustus": 8, "agu": 8, "agt": 8, "aug": 8, "august": 8,
    "september": 9, "sep": 9, "sept": 9,
    "oktober": 10, "okt": 10, "oct": 10, "october": 10,
    "november": 11, "nov": 11,
    "desember": 12, "des": 12, "dec": 12, "december": 12,
}  # fmt: skip

_BIRTH_LABELS = frozenset({"lahir", "ttl", "dob", "birth", "born"})
_AGE_LABELS = frozenset({"umur", "usia", "berumur", "berusia", "age"})
_POSTAL_LABELS = frozenset({"kode pos", "kodepos", "postal code", "zip"})
_GEO_LABELS = frozenset({"koordinat", "lokasi", "gps", "latitude", "longitude", "titik", "posisi", "location"})
_ADDRESS_MARKERS = frozenset({"jl.", "jl ", "jln", "jalan", "gg.", "gg ", "gang"})

_DATE_NUMERIC = re.compile(r"(?<![\d/.\-])(\d{1,2})[/\-.](\d{1,2})[/\-.](\d{4})(?![\d/.\-])")
_DATE_ISO = re.compile(r"(?<![\d\-])(\d{4})-(\d{2})-(\d{2})(?![\d\-])")
_DATE_TEXT = re.compile(r"(?<!\d)(\d{1,2})\s+([A-Za-z]{3,9})\.?\s+(\d{4})(?!\d)")
_BIRTH_LABEL_BEFORE = re.compile(r"(?:lahir|ttl|dob|birth|born)\b[^0-9]{0,40}$", re.IGNORECASE)

_AGE_RE = re.compile(
    r"\b(?:umur|usia|berumur|berusia|age)\b\s*[:=]?\s*(\d{1,3})(?:\s*(?:tahun|thn|th|years?)\b)?", re.I
)
_POSTAL_RE = re.compile(r"\b(?:kode\s*pos|kodepos|postal\s*code|zip)\b\s*[:=]?\s*([1-9]\d{4})(?!\d)", re.I)
_GEO_RE = re.compile(r"(?<!\d)(-?\d{1,2}\.\d{5,})\s*,\s*(-?\d{1,3}\.\d{5,})(?!\d|\.\d)")
_GEO_LABEL_BEFORE = re.compile(
    r"(?:koordinat|lokasi|gps|latitude|longitude|lat|long|titik|posisi|location)\b[^0-9\-]{0,30}$", re.I
)

_NAME = r"[A-Z][A-Za-z']*(?: [A-Z][A-Za-z']*){0,2}"  # an area name: up to three capitalised words, no full stop
_STREET = r"[A-Z][A-Za-z0-9'.]*(?: [A-Z0-9][A-Za-z0-9'.]*){0,4}"
_DETAIL = (
    r"(?:,?\s*(?i:No|Nomor|Blok)\.?\s*[A-Za-z0-9/\-]{1,6}"
    r"|,?\s*(?i:RT)\.?\s*\d{1,3}\s*[/,]?\s*(?i:RW)\.?\s*\d{1,3}"
    rf"|,?\s*(?i:Kel|Kelurahan|Desa|Kec|Kecamatan|Kab|Kabupaten|Kota)\.?\s+{_NAME})"
)
_ADDRESS_RE = re.compile(rf"\b(?i:Jl|Jln|Jalan|Gg|Gang)\.?\s+{_STREET}{_DETAIL}+")
# One administrative component ("Kel. Menteng"). Only these are kept when an address is generalised, so house
# numbers, RT/RW and the street never survive.
_AREA_WORD = r"(?:Kel|Kelurahan|Desa|Kec|Kecamatan|Kab|Kabupaten|Kota)"
_AREA_NAME = (
    r"[A-Z][A-Za-z']*(?: (?!(?:No|Nomor|RT|RW|Blok|" + _AREA_WORD + r")\b)[A-Z][A-Za-z']*){0,2}"
)  # a name stops at the next marker, so "Kel. Menteng No. 5" keeps only "Menteng"
_AREA_PART_RE = re.compile(rf"(?i:\b{_AREA_WORD}\.?)\s+{_AREA_NAME}")


def _valid_date(year: int, month: int, day: int) -> bool:
    try:
        date(year, month, day)
    except ValueError:
        return False
    return 1900 <= year <= date.today().year


def find_birthdate(text: str) -> list[PIIMatch]:
    if not mentions_any(text, _BIRTH_LABELS):
        return []
    candidates: list[tuple[int, int, int, int, int]] = []  # start, end, year, month, day
    for m in _DATE_NUMERIC.finditer(text):
        day, month, year = int(m.group(1)), int(m.group(2)), int(m.group(3))
        candidates.append((m.start(), m.end(), year, month, day))
    for m in _DATE_ISO.finditer(text):
        candidates.append((m.start(), m.end(), int(m.group(1)), int(m.group(2)), int(m.group(3))))
    for m in _DATE_TEXT.finditer(text):
        month = _MONTHS.get(m.group(2).lower())
        if month:
            candidates.append((m.start(), m.end(), int(m.group(3)), month, int(m.group(1))))
    out = []
    for start, end, year, month, day in candidates:
        if not _valid_date(year, month, day):
            continue
        if _BIRTH_LABEL_BEFORE.search(text[max(0, start - 60) : start]):
            out.append(PIIMatch("ID_BIRTHDATE", start, end, text[start:end], 0.85, {"year": year}))
    return out


def find_age(text: str) -> list[PIIMatch]:
    if not mentions_any(text, _AGE_LABELS):
        return []
    out = []
    for m in _AGE_RE.finditer(text):
        age = int(m.group(1))
        if 0 < age <= 120:
            out.append(PIIMatch("ID_AGE", m.start(1), m.end(), text[m.start(1) : m.end()], 0.8, {"age": age}))
    return out


def find_postal_code(text: str) -> list[PIIMatch]:
    if not mentions_any(text, _POSTAL_LABELS):
        return []
    return [
        PIIMatch("ID_POSTAL_CODE", m.start(1), m.end(1), m.group(1), 0.85, {"code": m.group(1)})
        for m in _POSTAL_RE.finditer(text)
    ]


def find_coordinates(text: str) -> list[PIIMatch]:
    if "." not in text or "," not in text or not mentions_any(text, _GEO_LABELS | {"lat", "long"}):
        return []
    out = []
    for m in _GEO_RE.finditer(text):
        lat, lon = float(m.group(1)), float(m.group(2))
        if abs(lat) > 90 or abs(lon) > 180:
            continue
        if _GEO_LABEL_BEFORE.search(text[max(0, m.start() - 40) : m.start()]):
            out.append(PIIMatch("GEO_COORDINATES", m.start(), m.end(), m.group(), 0.85, {"lat": lat, "lon": lon}))
    return out


def find_address(text: str) -> list[PIIMatch]:
    if not mentions_any(text, _ADDRESS_MARKERS):
        return []
    out = []
    for m in _ADDRESS_RE.finditer(text):
        parts = [p.group() for p in _AREA_PART_RE.finditer(m.group())]
        out.append(PIIMatch("ID_ADDRESS", m.start(), m.end(), m.group(), 0.8, {"area": ", ".join(parts) or None}))
    return out


def _decade(match: PIIMatch) -> str:
    age = match.meta["age"]
    low = age // 10 * 10
    return f"{low}-{low + 9} tahun"


# entity -> function(match) -> the generalised text, or None to fall back to the plain token.
GENERALIZERS = {
    "ID_BIRTHDATE": lambda m: str(m.meta["year"]),
    "ID_AGE": _decade,
    "ID_POSTAL_CODE": lambda m: m.meta["code"][:3] + "**",
    "ID_ADDRESS": lambda m: m.meta.get("area"),
    "GEO_COORDINATES": lambda m: f"{round(m.meta['lat'], 1)}, {round(m.meta['lon'], 1)}",
}
