"""Synthetic, structurally valid Indonesian identifiers for tests and benchmarks.

Every value here is generated — never use real people's data in tests.
"""

from __future__ import annotations

import random

from .pii.npwp import luhn_valid
from .pii.phone import OPERATOR_PREFIXES
from .pii.wilayah import kecamatan_codes


def _rng(seed: int | None) -> random.Random:
    return random.Random(seed)


def nik(seed: int | None = None, female: bool | None = None) -> str:
    r = _rng(seed)
    code = r.choice(sorted(kecamatan_codes()))
    dd = r.randint(1, 28)
    if female if female is not None else r.random() < 0.5:
        dd += 40
    return f"{code}{dd:02d}{r.randint(1, 12):02d}{r.randint(0, 99):02d}{r.randint(1, 9999):04d}"


def _luhn_complete(prefix: str) -> str:
    for d in "0123456789":
        if luhn_valid(prefix + d):
            return prefix + d
    raise AssertionError("unreachable")


def npwp(seed: int | None = None, formatted: bool = True) -> str:
    r = _rng(seed)
    first9 = _luhn_complete(f"{r.choice([1, 2, 3, 7, 8, 9]):02d}" + "".join(str(r.randint(0, 9)) for _ in range(6)))
    rest = f"{r.randint(0, 999):03d}{r.randint(0, 999):03d}"
    d = first9 + rest
    if not formatted:
        return d
    return f"{d[0:2]}.{d[2:5]}.{d[5:8]}.{d[8]}-{d[9:12]}.{d[12:15]}"


def phone(seed: int | None = None, international: bool = False) -> str:
    r = _rng(seed)
    p = r.choice(sorted(OPERATOR_PREFIXES))
    rest = "".join(str(r.randint(0, 9)) for _ in range(8))
    return f"+62{p[1:]}{rest}" if international else f"{p}{rest}"


def bpjs_kesehatan(seed: int | None = None) -> str:
    r = _rng(seed)
    return "000" + "".join(str(r.randint(0, 9)) for _ in range(10))


def nip(seed: int | None = None) -> str:
    """18-digit NIP: birth date + appointment month + gender + serial."""
    r = _rng(seed)
    year = r.randint(1960, 2000)
    tmt_year = year + r.randint(20, 30)
    return (
        f"{year}{r.randint(1, 12):02d}{r.randint(1, 28):02d}"
        f"{tmt_year}{r.randint(1, 12):02d}{r.randint(1, 2)}{r.randint(1, 999):03d}"
    )


def nisn(seed: int | None = None) -> str:
    return digits(10, seed)


def passport(seed: int | None = None) -> str:
    r = _rng(seed)
    return r.choice("ABCDEFGHJKLMNPRSTUVWXYZ") + digits(7, seed)


def sim(seed: int | None = None) -> str:
    return digits(12, seed)


def digits(n: int, seed: int | None = None) -> str:
    r = _rng(seed)
    return str(r.randint(1, 9)) + "".join(str(r.randint(0, 9)) for _ in range(n - 1))
