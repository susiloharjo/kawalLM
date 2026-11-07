import pytest
from helpers import shape

from kawallm import KawalLM, KawalLMEngine, synthetic
from kawallm.pii import detect_pii, find_nip, find_nisn, find_passport, find_sim, validate_nip

NIP = "199001012020011001"


def test_validate_nip():
    assert validate_nip(NIP)
    assert validate_nip("19900101 202001 1 001")
    assert not validate_nip("199013012020011001")  # month 13
    assert not validate_nip("199002302020011001")  # 30 February
    assert not validate_nip("199001012020131001")  # appointment month 13
    assert not validate_nip("199001012005011001")  # appointed at age 15
    assert not validate_nip("199001012020013001")  # gender digit must be 1 or 2
    assert not validate_nip("1990010120200110")  # too short


def test_nip_found_without_keyword_in_several_formats():
    for form in (NIP, "19900101 202001 1 001", "19900101-202001-1-001"):
        assert [m.text for m in find_nip(f"pegawai {form} aktif")] == [form]


def test_nip_not_found_inside_longer_digit_runs_or_when_invalid():
    assert find_nip(f"9{NIP}") == []
    assert find_nip(f"{NIP}9") == []
    assert find_nip("resi 123456789012345678") == []  # 18-digit tracking number
    assert find_nip("kode 999999999999999999") == []


def test_nisn_needs_keyword():
    assert [m.text for m in find_nisn("NISN siswa: 0051234567")] == ["0051234567"]
    assert find_nisn("nomor 0051234567") == []
    assert find_nisn("NISN 00512345678") == []  # 11 digits


def test_passport_needs_keyword_and_shape():
    assert [m.text for m in find_passport("No. paspor X1234567 berlaku")] == ["X1234567"]
    assert [m.text for m in find_passport("passport: A 1234567")] == ["A 1234567"]
    assert find_passport("kode X1234567") == []
    assert find_passport("paspor x1234567") == []  # printed in capitals
    assert find_passport("paspor XY1234567") == []


def test_sim_needs_keyword():
    assert [m.text for m in find_sim("Nomor SIM A: 1234 5678 9012")] == ["1234 5678 9012"]
    assert [m.text for m in find_sim("surat izin mengemudi 123456789012")] == ["123456789012"]
    assert find_sim("nomor 123456789012") == []
    assert find_sim("SIM 12345678901") == []  # 11 digits


@pytest.mark.parametrize("seed", range(40))
def test_synthetic_roundtrip_and_no_collision_with_other_detectors(seed):
    cases = [
        ("ID_NIP", f"data {synthetic.nip(seed)} selesai"),
        ("ID_NISN", f"NISN {synthetic.nisn(seed)} selesai"),
        ("ID_PASSPORT", f"paspor {synthetic.passport(seed)} selesai"),
        ("ID_SIM", f"SIM {synthetic.sim(seed)} selesai"),
    ]
    for entity, text in cases:
        assert [m.entity for m in detect_pii(text)] == [entity], text


def test_masking_and_reversible_roundtrip():
    text = f"NIP {NIP}, NISN 0051234567, paspor X1234567, SIM 123456789012"
    assert KawalLM().scan(text).sanitized_text == "NIP <ID_NIP>, NISN <ID_NISN>, paspor <ID_PASSPORT>, SIM <ID_SIM>"
    e = KawalLMEngine(mode="reversible")
    r = e.mask(text)
    assert shape(r.text) == "NIP <ID_NIP_1>, NISN <ID_NISN_1>, paspor <ID_PASSPORT_1>, SIM <ID_SIM_1>"
    assert e.unmask(r.text, r.session_id) == text


def test_entities_option_limits_detection():
    text = f"NIP {NIP} dan HP 081234567890"
    assert [m.entity for m in detect_pii(text, ("ID_NIP",))] == ["ID_NIP"]
    assert [m.entity for m in detect_pii(text, ("ID_PHONE",))] == ["ID_PHONE"]
