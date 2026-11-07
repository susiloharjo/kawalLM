import pytest

from kawallm import KawalLM
from kawallm.pii import detect_pii, find_phone
from kawallm.pii.landline import find_landline, split_landline


@pytest.mark.parametrize(
    "text,expected",
    [
        ("Telp (021) 5551234", "(021) 5551234"),
        ("kantor (0274) 556677 buka", "(0274) 556677"),
        ("hubungi (031)5551234", "(031)5551234"),
        ("hubungi 021-5551234 ya", "021-5551234"),
        ("hubungi 021 5551234 ya", "021 5551234"),
        ("hubungi 021.5551234 ya", "021.5551234"),
        ("hubungi 0274-556677", "0274-556677"),
        ("hubungi 0361 223344", "0361 223344"),
        ("cs +62 21 5551234 aktif", "+62 21 5551234"),
        ("cs +6221-5551234 aktif", "+6221-5551234"),
        ("telp 0215551234", "0215551234"),  # no separator, keyword present
        ("Fax: 02255512345", "02255512345"),
        ("Hotline 62215551234", "62215551234"),
    ],
)
def test_landline_detected(text, expected):
    matches = find_landline(text)
    assert [m.text for m in matches] == [expected], text
    assert all(m.entity == "ID_PHONE" and m.meta["landline"] for m in matches)


@pytest.mark.parametrize(
    "text",
    [
        "nomor 0215551234",  # unseparated, no keyword
        "angka 62215551234 muncul",  # bare 62 prefix, no keyword
        "tanggal 12-05-2024 pukul 10.30",
        "versi 0.9.1234567 dirilis",
        "IP 10.80.199.27 dan 010.080.199.027",
        "kode pos 40111, ext 5551234",
        "021-55512",  # subscriber too short
        "021-555123456789",  # subscriber too long
        "(021) 55512",  # too short even in parentheses
        "099-1234567",  # unknown area code
        "pesanan 20241107001 selesai",
        "resi 1234567890123456",
    ],
)
def test_not_landline(text):
    assert find_landline(text) == [], text


def test_split_landline_prefers_known_area_code_over_greedy_parse():
    assert split_landline("+62 215551234") == ("021", "5551234")
    assert split_landline("0251234567") == ("0251", "234567")
    assert split_landline("0991234567") is None


def test_mobile_detection_unchanged_and_no_overlap():
    text = "HP 081234567890 dan telp (021) 5551234"
    found = detect_pii(text)
    assert [m.text for m in found] == ["081234567890", "(021) 5551234"]
    assert [m.meta.get("operator") for m in find_phone("081234567890")] == ["Telkomsel"]


def test_masking_and_reversible_roundtrip():
    g = KawalLM()
    assert g.scan("Telp (021) 5551234, fax 021-5559876").sanitized_text == "Telp <ID_PHONE>, fax <ID_PHONE>"
    text, m = g.anonymize("kantor 021-5551234 dan HP 081234567890")
    assert g.deanonymize(text, m) == "kantor 021-5551234 dan HP 081234567890"


def test_does_not_steal_other_identifiers():
    nik = "3171011501900001"
    assert [m.entity for m in detect_pii(f"NIK {nik}")] == ["ID_NIK"]
    assert [m.entity for m in detect_pii("BCA 1234567890")] == ["ID_BANK_ACCOUNT"]
