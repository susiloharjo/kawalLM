import pytest

from kawallm import synthetic
from kawallm.pii import detect_pii, find_bank_account, find_bpjs, find_email, find_phone, find_plate, phone_operator
from kawallm.pii.base import PIIMatch, has_keyword_near, resolve_overlaps


@pytest.mark.parametrize(
    "num,op",
    [
        ("081234567890", "Telkomsel"),
        ("+62 857-1234-5678", "Indosat"),
        ("6289612345678", "Tri"),
        ("0877 1234 5678", "XL"),
        ("083812345678", "Axis"),
        ("088812345678", "Smartfren"),
    ],
)
def test_phone_operators(num, op):
    assert phone_operator(num) == op
    assert [m.meta["operator"] for m in find_phone(f"hubungi {num} ya")] == [op]


def test_phone_rejects_unknown_prefix_and_length():
    assert phone_operator("080012345678") is None
    assert phone_operator("08123") is None
    assert find_phone("kode 0800-1234-5678") == []


def test_synthetic_phones():
    for s in range(50):
        assert find_phone(synthetic.phone(s)), synthetic.phone(s)
        assert find_phone(synthetic.phone(s, international=True))


def test_bank_proximity_and_length():
    assert [m.meta["bank"] for m in find_bank_account("transfer ke BCA 1234567890 ya")] == ["bca"]
    assert find_bank_account("rekening mandiri 123-00-1234567-8")[0].meta["bank"] == "mandiri"
    # BCA must be 10 digits
    assert find_bank_account("BCA 123456789012") == []
    # bank too far away (> 5 words)
    assert find_bank_account("BCA itu bank yang sangat besar sekali di kota 1234567890") == []
    # generic keyword
    assert find_bank_account("no rek 123456789012")[0].score < 0.9
    assert find_bank_account("ID pesanan 1234567890") == []
    # mixed separators (e.g. date + time near 'transfer') must not match as bank account
    assert find_bank_account("bukti transfer tanggal 2026-11-07 20.45") == []


def test_bank_after_number():
    assert find_bank_account("1234567890 (BCA a.n. Budi)")[0].meta["bank"] == "bca"


def test_bpjs():
    kes = synthetic.bpjs_kesehatan(1)
    assert [m.entity for m in find_bpjs(f"kartu {kes}")] == ["ID_BPJS_KES"]
    assert [m.entity for m in find_bpjs("No BPJS 1234567890123")] == ["ID_BPJS_KES"]
    assert find_bpjs("kode 1234567890123") == []
    assert [m.entity for m in find_bpjs("KPJ 12345678901")] == ["ID_BPJS_TK"]
    assert find_bpjs("order 12345678901") == []


def test_plate():
    assert [m.text for m in find_plate("Mobil B 1234 ABC dan motor AB 12 CD")] == ["B 1234 ABC", "AB 12 CD"]
    assert find_plate("QQ 1234 ABC") == []
    assert find_plate("b 1234 abc") == []


def test_email():
    assert [m.text for m in find_email("kirim ke budi.s+ai@mail.co.id ya")] == ["budi.s+ai@mail.co.id"]


def test_overlap_resolution_prefers_priority():
    a = PIIMatch("ID_PHONE", 0, 12, "x")
    b = PIIMatch("ID_NIK", 0, 16, "y")
    assert resolve_overlaps([a, b]) == [b]


def test_keyword_near():
    assert has_keyword_near("ini nomor NPWP saya 123", 20, 23, frozenset({"npwp"})) == "npwp"
    assert has_keyword_near("123 adalah NPWP", 0, 3, frozenset({"npwp"})) == "npwp"
    assert has_keyword_near("123", 0, 3, frozenset({"npwp"})) is None


def test_detect_pii_fast_path_and_filter():
    assert detect_pii("") == []
    assert detect_pii("halo semua apa kabar") == []
    t = "HP 081234567890 email a@b.co"
    assert [m.entity for m in detect_pii(t, ("EMAIL",))] == ["EMAIL"]


def test_bank_keyword_farther_than_100_chars_still_counts():
    """The keyword window must stay at 120 characters; a 100-character window missed 'transfer' here."""
    text = "transfer" + " 939692975:0535707991268485049019681988039238699900148-1193936124509742985915" + " 56960003581"
    assert [m.text for m in find_bank_account(text)] == ["56960003581"]
