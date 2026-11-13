"""Technical and everyday text that resembles an identifier, and must keep passing through (or still be masked)."""

import pytest

from kawallm import KawalLM


@pytest.mark.parametrize(
    "text",
    [
        "kernel 6.1.0.13 dipakai di server itu",
        "build 1.2.3.4 lolos CI",
        "release 10.20.30.40 tersedia",
        "pip install pkg==1.2.3.4",
        "requires foo>=1.2.3.4 dan bar~=2.3.4.5",
        "npm i baz@^1.2.3.4",
        "firmware 1.2.3.4-rc1 diuji",
        "versi 1.2.3.4+build5 dirilis",
        "Kelas A 1234 BC dimulai pukul 8",
        "Rute B 1234 AB menuju terminal",
        "Blok D 1234 EF dan Lantai B 1234 AB",
        "Rp 0812345678 juta",
        "total IDR 081234567890 dan $ 081234567890",
    ],
)
def test_lookalikes_are_not_masked(text):
    assert KawalLM().scan(text).sanitized_text == text


@pytest.mark.parametrize(
    "text,expected",
    [
        ("server di 103.28.12.5 down", "server di <IP_ADDRESS> down"),
        ("ssh admin@103.28.12.5", "ssh admin@<IP_ADDRESS>"),
        ("host=45.33.32.156 port=22", "host=<IP_ADDRESS> port=22"),
        ("rentang 8.8.8.1-8.8.8.9", "rentang <IP_ADDRESS>-<IP_ADDRESS>"),
        ("Plat B 1234 ABC milik pak Budi", "Plat <ID_PLATE> milik pak Budi"),
        ("Kendaraan D 4321 XY terparkir", "Kendaraan <ID_PLATE> terparkir"),
        ("HP 081234567890", "HP <ID_PHONE>"),
        ("bayar Rp 50.000 ke 081234567890", "bayar Rp 50.000 ke <ID_PHONE>"),
    ],
)
def test_real_identifiers_are_still_masked(text, expected):
    assert KawalLM().scan(text).sanitized_text == expected
