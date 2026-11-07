"""NIK (Nomor Induk Kependudukan) detection with semantic validation.

Structure (16 digits): PP KK CC DDMMYY SSSS
  - PPKKCC  : provinsi / kab-kota / kecamatan code (Kemendagri)
  - DDMMYY  : birth date; women have DD + 40
  - SSSS    : serial, never 0000

A 16-digit string that fails validation is NOT treated as a NIK (avoids false
positives on resi, barcode, inventory serials).

Note: the Kartu Keluarga (KK) number shares the same structure, so a valid KK
number is also reported as ID_NIK. Both are personal data under UU PDP.
"""

from __future__ import annotations

import calendar
import re
from datetime import date

from .base import PIIMatch
from .wilayah import is_valid_kecamatan, lookup

# 16 digits, optionally grouped as 4-4-4-4 / 6-6-4 with spaces, dots or dashes.
NIK_RE = re.compile(
    r"(?<![\d])(?:[1-9]\d{15}"
    r"|[1-9]\d{3}[ .-]\d{4}[ .-]\d{4}[ .-]\d{4}"
    r"|[1-9]\d{5}[ .-]\d{6}[ .-]\d{4})(?![\d])"
)


def _birth_date(dd: int, mm: int, yy: int) -> tuple[date | None, str | None]:
    sex = "L"
    if dd > 40:
        dd -= 40
        sex = "P"
    if not (1 <= mm <= 12 and 1 <= dd <= 31):
        return None, None
    # Two-digit year is ambiguous; try 19xx and 20xx, keep the first real date.
    for century in (1900, 2000):
        year = century + yy
        if dd <= calendar.monthrange(year, mm)[1]:
            return date(year, mm, dd), sex
    return None, None


def validate_nik(nik: str, check_region: bool = True) -> bool:
    nik = "".join(ch for ch in nik if ch.isdigit())
    if len(nik) != 16 or nik[0] == "0":
        return False
    if nik[12:] == "0000":
        return False
    born, _ = _birth_date(int(nik[6:8]), int(nik[8:10]), int(nik[10:12]))
    if born is None:
        return False
    if check_region and not is_valid_kecamatan(nik[:6]):
        return False
    return True


def parse_nik(nik: str) -> dict | None:
    """Decode a valid NIK into region, birth date and sex. Returns None if invalid."""
    nik = "".join(ch for ch in nik if ch.isdigit())
    if not validate_nik(nik):
        return None
    born, sex = _birth_date(int(nik[6:8]), int(nik[8:10]), int(nik[10:12]))
    return {
        "wilayah": lookup(nik[:6]),
        "kode_wilayah": nik[:6],
        "tanggal_lahir_ddmmyy": nik[6:12],
        "jenis_kelamin": sex,
        "serial": nik[12:],
        # Year is reported as candidates because YY is ambiguous.
        "bulan": born.month if born else None,
        "tanggal": born.day if born else None,
    }


def find_nik(text: str, check_region: bool = True) -> list[PIIMatch]:
    out = []
    for m in NIK_RE.finditer(text):
        if validate_nik(m.group(), check_region=check_region):
            out.append(PIIMatch("ID_NIK", m.start(), m.end(), m.group(), 1.0))
    return out
