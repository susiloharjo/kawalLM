import pytest
from helpers import shape

from kawallm import KawalLM, KawalLMEngine
from kawallm.pii import detect_pii, find_ip


@pytest.mark.parametrize(
    "text,expected",
    [
        ("server 103.80.199.27 aktif", ["103.80.199.27"]),
        ("klien 103.28.12.45:8080 terhubung", ["103.28.12.45"]),
        ("subnet 103.168.1.10/24", ["103.168.1.10"]),
        ("dari 103.28.12.5, ke 45.33.32.156.", ["103.28.12.5", "45.33.32.156"]),
        ("(103.16.0.5)", ["103.16.0.5"]),
        ("v6 publik 2a00:1450:4001::1111 dan 2a00:1450:4001::68", ["2a00:1450:4001::1111", "2a00:1450:4001::68"]),
        ("v6 2606:4700:4700::8a2e:370:7334 ok", ["2606:4700:4700::8a2e:370:7334"]),
        ("penuh 2606:4700:85a3:0000:0000:8a2e:0370:7334 selesai", ["2606:4700:85a3:0000:0000:8a2e:0370:7334"]),
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
    assert (
        g.scan("akses dari 103.28.12.45 dan 2a00:1450:4001::1111").sanitized_text
        == "akses dari <IP_ADDRESS> dan <IP_ADDRESS>"
    )
    e = KawalLMEngine(mode="reversible")
    r = e.mask("klien 103.28.12.45 lalu 103.28.12.45 dan 103.28.12.7")
    assert shape(r.text) == "klien <IP_ADDRESS_1> lalu <IP_ADDRESS_1> dan <IP_ADDRESS_2>"
    assert e.unmask(r.text, r.session_id) == "klien 103.28.12.45 lalu 103.28.12.45 dan 103.28.12.7"
    # rewritten by the LLM
    tok = r.text.split()[1]
    assert e.unmask(f"[{tok.strip('<>').lower()}]", r.session_id) == "103.28.12.45"
    # opt out
    assert KawalLMEngine(entities=("ID_NIK",)).mask_pii("IP 103.28.12.45") == "IP 103.28.12.45"


def test_does_not_steal_other_identifiers():
    assert [m.entity for m in detect_pii("HP 081234567890 dari 103.28.12.45")] == ["ID_PHONE", "IP_ADDRESS"]
    assert [m.entity for m in detect_pii("NPWP 09.254.294.3-407.000")] in ([], ["ID_NPWP"])
