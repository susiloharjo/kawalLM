import pytest

from kawallm import KawalLM
from kawallm.pii import detect_pii


def test_bpjs_entity_names_are_accepted_and_filtered():
    text = "BPJS 0001234567890 dan kartu ketenagakerjaan 12345678901"
    assert [m.entity for m in detect_pii(text, ("ID_BPJS_KES",))] == ["ID_BPJS_KES"]
    assert [m.entity for m in detect_pii(text, ("ID_BPJS_TK",))] == ["ID_BPJS_TK"]
    assert [m.entity for m in detect_pii(text, ("ID_BPJS",))] == ["ID_BPJS_KES", "ID_BPJS_TK"]


def test_masking_with_bpjs_entity_name_does_not_crash():
    assert KawalLM(entities=["ID_BPJS_KES"]).mask_pii("BPJS 0001234567890") == "BPJS <ID_BPJS_KES>"
    assert KawalLM(entities=["ID_BPJS_TK"]).mask_pii("BPJS 0001234567890") == "BPJS 0001234567890"


def test_unknown_entity_name_is_a_clear_error():
    with pytest.raises(ValueError, match="unknown entity 'ID_FOO'"):
        detect_pii("halo", ("ID_FOO",))
