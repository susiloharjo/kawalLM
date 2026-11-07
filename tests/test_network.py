import pytest
from helpers import shape

from kawallm import KawalLM, KawalLMEngine
from kawallm.pii import detect_pii, find_ip


@pytest.mark.parametrize(
    "text,expected",
    [
        ("server 10.80.199.27 aktif", ["10.80.199.27"]),
        ("klien 203.0.113.45:8080 terhubung", ["203.0.113.45"]),
        ("subnet 192.168.1.10/24", ["192.168.1.10"]),
        ("dari 8.8.8.8, ke 1.1.1.1.", ["8.8.8.8", "1.1.1.1"]),
        ("(172.16.0.5)", ["172.16.0.5"]),
        ("loopback ::1 dan fe80::1", ["::1", "fe80::1"]),
        ("v6 2001:db8::8a2e:370:7334 ok", ["2001:db8::8a2e:370:7334"]),
        ("penuh 2001:0db8:85a3:0000:0000:8a2e:0370:7334 selesai", ["2001:0db8:85a3:0000:0000:8a2e:0370:7334"]),
    ],
)
def test_ip_detected(text, expected):
    assert [m.text for m in find_ip(text)] == expected
    assert all(m.entity == "IP_ADDRESS" for m in find_ip(text))


@pytest.mark.parametrize(
    "text",
    [
        "Build 10.0.19045.2965 terpasang",  # octet above 255
        "angka 010.080.199.027 lama",  # leading zeros
        "versi 1.2.3.4 dirilis",
        "v1.2.3.4 dirilis",
        "version 2.3.4.5 dirilis",
        "256.1.1.1 bukan IP",
        "1.2.3 hanya tiga bagian",
        "tanggal 10.05.2024 pukul 10.30",
        "waktu 10:30:45 selesai",
        "MAC aa:bb:cc:dd:ee:ff perangkat",
        "std::vector dan Add::Bad dan Dead::Beef",
        "resi 1234567890123456",
        "NPWP 09.254.294.3-407.000",
        "a1.2.3.4 menempel",
    ],
)
def test_not_ip(text):
    assert find_ip(text) == [], text


def test_masking_reversible_and_entity_option():
    g = KawalLM()
    assert g.scan("akses dari 203.0.113.45 dan ::1").sanitized_text == "akses dari <IP_ADDRESS> dan <IP_ADDRESS>"
    e = KawalLMEngine(mode="reversible")
    r = e.mask("klien 203.0.113.45 lalu 203.0.113.45 dan 198.51.100.7")
    assert shape(r.text) == "klien <IP_ADDRESS_1> lalu <IP_ADDRESS_1> dan <IP_ADDRESS_2>"
    assert e.unmask(r.text, r.session_id) == "klien 203.0.113.45 lalu 203.0.113.45 dan 198.51.100.7"
    # rewritten by the LLM
    tok = r.text.split()[1]
    assert e.unmask(f"[{tok.strip('<>').lower()}]", r.session_id) == "203.0.113.45"
    # opt out
    assert KawalLMEngine(entities=("ID_NIK",)).mask_pii("IP 203.0.113.45") == "IP 203.0.113.45"


def test_does_not_steal_other_identifiers():
    assert [m.entity for m in detect_pii("HP 081234567890 dari 203.0.113.45")] == ["ID_PHONE", "IP_ADDRESS"]
    assert [m.entity for m in detect_pii("NPWP 09.254.294.3-407.000")] in ([], ["ID_NPWP"])
