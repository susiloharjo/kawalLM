"""Quasi-identifiers (opt-in ``extended`` profile): detection, generalisation, profiles and the audit flag."""

from pathlib import Path

import pytest
from helpers import shape

from kawallm import AuditLog, KawalLM, KawalLMEngine
from kawallm.pii import ALL_ENTITIES, PROFILES, QUASI_ENTITIES, detect_pii, expand_entities
from kawallm.pii.quasi import find_address, find_age, find_birthdate, find_coordinates, find_postal_code

ADDRESS = "Jl. Sudirman No. 5, RT 3/RW 4, Kel. Menteng, Kec. Menteng, Kota Jakarta Pusat"
FULL = (
    f"Lahir: 12 Mei 1990, usia 34 tahun, kode pos 10110. Alamat {ADDRESS}. "
    "Koordinat -6.208763, 106.845599. NIK 3171011501900001"
)


# ---------------------------------------------------------------- opt-in
def test_quasi_entities_are_not_in_the_default_set():
    assert not set(QUASI_ENTITIES) & set(ALL_ENTITIES)
    assert detect_pii(FULL) and {m.entity for m in detect_pii(FULL)} == {"ID_NIK"}
    assert KawalLM().scan(FULL).sanitized_text.count("<") == 1  # only the NIK


def test_profiles_expand_to_their_members():
    assert expand_entities("core") == ALL_ENTITIES
    assert set(expand_entities("extended")) == set(ALL_ENTITIES) | set(QUASI_ENTITIES)
    assert expand_entities(["extended"]) == expand_entities("extended")
    assert set(expand_entities("core, ID_AGE")) == set(ALL_ENTITIES) | {"ID_AGE"}
    assert PROFILES["extended"] == (*ALL_ENTITIES, *QUASI_ENTITIES)


def test_unknown_entity_and_engine_accepts_profile_names():
    with pytest.raises(ValueError, match="unknown entity"):
        detect_pii("halo 1", ("ID_NOPE",))
    assert set(KawalLMEngine(entities="extended").entities) == set(PROFILES["extended"])


def test_extended_profile_finds_every_quasi_identifier():
    assert {m.entity for m in detect_pii(FULL, "extended")} == {"ID_NIK", *QUASI_ENTITIES}


# ---------------------------------------------------------------- birth date
@pytest.mark.parametrize(
    "text,year",
    [
        ("Tanggal lahir: 12 Mei 1990", 1990),
        ("TTL Jakarta, 01-02-1985", 1985),
        ("tgl lahir 5/11/2001", 2001),
        ("DOB 1979-03-04", 1979),
        ("lahir pada 17 Agustus 1945", 1945),
        ("Born 3 March 1992", 1992),
    ],
)
def test_birthdate_detected_with_a_label(text, year):
    (m,) = find_birthdate(text)
    assert m.entity == "ID_BIRTHDATE" and m.meta["year"] == year


@pytest.mark.parametrize(
    "text",
    [
        "Rapat dijadwalkan 12-05-2024 pukul 10.30",  # a date, but not a birth date
        "Tanggal lahir: 31 Februari 1990",  # impossible date
        "Tanggal lahir: 12 Mei 3024",  # year in the future
        "Tanggal lahir: 12 Mei 1850",  # before 1900
        "lahir 99/99/1990",
        "Kami lahir kembali pada era baru tanpa angka",
    ],
)
def test_birthdate_not_detected_without_label_or_with_invalid_date(text):
    assert find_birthdate(text) == []


# ---------------------------------------------------------------- age
def test_age_needs_a_label_and_a_plausible_value():
    assert [m.meta["age"] for m in find_age("Usia 34 tahun, umur: 5, berumur 61 th")] == [34, 5, 61]
    assert find_age("usia 200 tahun") == []
    assert find_age("usia 0 tahun") == []
    assert find_age("kecepatan 34 km per jam dan 40 tahun lalu") == []


# ---------------------------------------------------------------- postal code
def test_postal_code_needs_a_label():
    assert [m.meta["code"] for m in find_postal_code("kode pos 10110, Kode Pos: 40111, ZIP 55281")] == [
        "10110",
        "40111",
        "55281",
    ]
    assert find_postal_code("nomor 10110 muncul begitu saja") == []
    assert find_postal_code("kode pos 01234") == []  # postal codes do not start with 0


# ---------------------------------------------------------------- coordinates
def test_coordinates_need_a_label_and_valid_ranges():
    (m,) = find_coordinates("Koordinat gudang -6.208763, 106.845599.")
    assert m.text == "-6.208763, 106.845599" and m.meta["lat"] == -6.208763
    assert find_coordinates("nilai 12.3456, 98.7654 tanpa label") == []
    assert find_coordinates("Koordinat 95.1234, 10.1234") == []  # latitude out of range
    assert find_coordinates("Koordinat -6.2, 106.8") == []  # too coarse to be a precise location
    assert find_coordinates("Koordinat gudang -6.2088, 106.8456") == []  # 4 decimals (~11 m): not precise enough


# ---------------------------------------------------------------- address
@pytest.mark.parametrize(
    "text,expected",
    [
        (f"Alamat {ADDRESS}. Koordinat", ADDRESS),
        ("Kunjungi Jl. Sudirman No. 5 besok", "Jl. Sudirman No. 5"),
        ("Jl. Melati, Kel. Menteng, Kec. Tebet", "Jl. Melati, Kel. Menteng, Kec. Tebet"),
        ("tinggal di Gang Mawar RT 2/RW 3", "Gang Mawar RT 2/RW 3"),
    ],
)
def test_address_span_stops_at_the_end_of_the_address(text, expected):
    (m,) = find_address(text)
    assert m.text == expected


@pytest.mark.parametrize(
    "text",
    [
        "Jalan tol Trans Jawa sudah dibuka",
        "Kami berjalan di jalan raya",
        "Jl. Sudirman macet",  # a street with no number, RT/RW or administrative area
        "jl. sudirman no. 5",  # street names are capitalised
    ],
)
def test_address_needs_a_marker_and_a_detail(text):
    assert find_address(text) == []


def test_address_without_any_digit_is_still_found():
    assert [m.entity for m in detect_pii("Jl. Melati, Kel. Menteng, Kec. Tebet", "extended")] == ["ID_ADDRESS"]


# ---------------------------------------------------------------- generalisation
def test_generalize_lowers_the_precision():
    out = KawalLM(entities="extended", mode="generalize").scan(FULL).sanitized_text
    assert "Lahir: 1990," in out and "12 Mei" not in out
    assert "usia 30-39 tahun" in out
    assert "kode pos 101**" in out and "10110" not in out
    assert "Alamat Kel. Menteng, Kec. Menteng, Kota Jakarta Pusat." in out and "Sudirman" not in out
    assert "Koordinat -6.2, 106.8." in out
    assert "<ID_NIK>" in out  # an ID number has no generalisation: it becomes the plain token


def test_generalize_falls_back_to_the_token_when_nothing_can_be_kept():
    out = KawalLM(entities="extended", mode="generalize").scan("Alamat Jl. Sudirman No. 5").sanitized_text
    assert out == "Alamat <ID_ADDRESS>"


def test_reversible_round_trip_with_quasi_identifiers():
    e = KawalLMEngine(entities="extended", mode="reversible")
    r = e.mask(FULL)
    assert shape(r.text).count("<") == 6
    assert e.unmask(r.text, r.session_id) == FULL


# ---------------------------------------------------------------- audit flag
def test_audit_flags_a_combination_of_quasi_identifiers():
    events = []
    guard = KawalLM(entities="extended", audit=AuditLog(events.append))
    guard.scan("Tanggal lahir: 12 Mei 1990, kode pos 10110")
    guard.scan("Tanggal lahir: 12 Mei 1990")
    guard.scan("halo")
    assert events[0].flags == ["combined_quasi_identifiers"]
    assert events[1].flags == [] and events[2].flags == []
    assert events[0].to_dict()["flags"] == ["combined_quasi_identifiers"]
    assert "1990" not in events[0].to_json() and "10110" not in events[0].to_json()


def test_two_of_the_same_type_are_not_a_combination():
    events = []
    KawalLM(entities="extended", audit=AuditLog(events.append)).scan("usia 34 tahun dan umur 40 tahun")
    assert events[0].entities == {"ID_AGE": 2} and events[0].flags == []


# ---------------------------------------------------------------- false positives
def test_benign_sentences_are_untouched_by_the_extended_profile():
    sentences = [
        line.strip()
        for line in (Path(__file__).parent / "data" / "benign_id.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    guard = KawalLM(entities="extended")
    changed = [s for s in sentences if guard.scan(s).sanitized_text != s]
    assert not changed, changed
