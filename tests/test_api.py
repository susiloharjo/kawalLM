"""The public high-level API, mirroring docs/usage.md."""

from kawallm import KawalLM, ScanResult, restore_tokens

NIK = "3171012304900001"  # 23-04-1990, Gambir — synthetic


def test_scan_sanitizes():
    guard = KawalLM(mask_pii=True, block_safety=True, validate_wilayah=True)
    r = guard.scan(f"Tolong bayar invoice ini ke rekening BCA 1234567890 an Eko, NIK saya {NIK}")
    assert isinstance(r, ScanResult)
    assert not r.is_blocked and r.is_safe and r.pii_found
    assert r.violation_reason == ""
    assert r.sanitized_text == "Tolong bayar invoice ini ke rekening BCA <ID_BANK_ACCOUNT> an Eko, NIK saya <ID_NIK>"


def test_scan_blocks_but_still_sanitizes():
    r = KawalLM().scan("link slot gacor maxwin, hubungi 081234567890")
    assert r.is_blocked
    assert "JUDOL_PINJOL" in r.violation_reason
    assert "<ID_PHONE>" in r.sanitized_text


def test_block_safety_false():
    r = KawalLM(block_safety=False).scan("slot gacor maxwin")
    assert not r.is_blocked and r.violation_reason == ""
    assert r.violations  # still reported


def test_validate_wilayah_toggle():
    unknown_region = "9999992304900001"
    assert KawalLM().scan(unknown_region).sanitized_text == unknown_region
    assert KawalLM(validate_wilayah=False).scan(unknown_region).sanitized_text == "<ID_NIK>"


def test_anonymize_deanonymize_stateless():
    guard = KawalLM(mode="reversible")
    text, session_map = guard.anonymize("Kirim SMS konfirmasi ke 081288889999 sekarang.")
    assert text == "Kirim SMS konfirmasi ke <ID_PHONE_1> sekarang."
    assert session_map == {"<ID_PHONE_1>": "081288889999"}
    reply = "Baik, konfirmasi berhasil dikirimkan ke <ID_PHONE_1>."
    assert guard.deanonymize(reply, session_map) == "Baik, konfirmasi berhasil dikirimkan ke 081288889999."
    # next turn keeps numbering
    text2, session_map = guard.anonymize("dan juga 081377776666 serta 081288889999", session_map)
    assert text2 == "dan juga <ID_PHONE_2> serta <ID_PHONE_1>"
    assert restore_tokens(text2, session_map) == "dan juga 081377776666 serta 081288889999"


def test_anonymize_disabled_or_empty():
    assert KawalLM(mask_pii=False).anonymize("081288889999") == ("081288889999", {})
    assert KawalLM().anonymize("") == ("", {})


def test_reversible_scan_uses_vault():
    guard = KawalLM(mode="reversible")
    r = guard.scan(f"NIK {NIK}")
    assert r.sanitized_text == "NIK <ID_NIK_1>"
    assert guard.unmask("ok <ID_NIK_1>", r.session_id) == f"ok {NIK}"
