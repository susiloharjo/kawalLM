import pytest

from kawallm import synthetic
from kawallm.pii import find_nik, parse_nik, validate_nik

# 3171 01 = Jakarta Pusat / Gambir (valid kecamatan code)
VALID_MALE = "3171011501900001"
VALID_FEMALE = "3171015501920002"  # DD 55 -> 15, female


def test_valid_male_and_female():
    assert validate_nik(VALID_MALE)
    assert validate_nik(VALID_FEMALE)
    assert parse_nik(VALID_MALE)["jenis_kelamin"] == "L"
    p = parse_nik(VALID_FEMALE)
    assert p["jenis_kelamin"] == "P"
    assert p["tanggal"] == 15
    assert p["wilayah"]["provinsi"]


@pytest.mark.parametrize(
    "value,why",
    [
        ("9999991501900001", "unknown region"),
        ("3171013201900001", "day 32"),
        ("3171017201900001", "female day 32"),
        ("3171011513900001", "month 13"),
        ("3171011500900001", "month 00"),
        ("3171013002900001", "30 Feb"),
        ("3171011501900000", "serial 0000"),
        ("0171011501900001", "leading zero"),
        ("317101150190001", "15 digits"),
    ],
)
def test_invalid(value, why):
    assert not validate_nik(value), why


def test_region_check_can_be_disabled():
    assert validate_nik("9999991501900001", check_region=False)


def test_feb_29_leap_year():
    assert validate_nik("3171012902000001")  # 29-02-2000


def test_find_in_text_and_formats():
    text = f"NIK saya {VALID_MALE}, punya istri 3171 0155 0192 0002."
    found = find_nik(text)
    assert [m.text for m in found] == [VALID_MALE, "3171 0155 0192 0002"]


def test_resi_and_barcode_not_masked():
    # 16 digits that fail semantic validation must be left alone (PRD FR-1.1 fallback)
    assert find_nik("Resi JNE 1234567890123456 dan barcode 8999999999999999") == []


def test_not_part_of_longer_number():
    assert find_nik("ref 31710115019000011") == []


def test_synthetic_niks_validate():
    for seed in range(200):
        n = synthetic.nik(seed)
        assert validate_nik(n), n


def test_parse_invalid_returns_none():
    assert parse_nik("123") is None
