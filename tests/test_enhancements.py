import pytest

from kawallm.core import KawalLMEngine
from kawallm.pii import detect_pii, find_bank_account, find_passport
from kawallm.safety import SafetyScanner, normalize


def test_mixed_spaced_obfuscation():
    assert normalize("s.l-o_t g-4.c_0-r") == " slot gacor "
    assert normalize("s.l.o.t g.4.c.0.r") == " slot gacor "
    assert normalize("s l o t") == " slot "
    assert normalize("s l o t g a c o r") == " slotgacor "

    scanner = SafetyScanner()
    assert not scanner.scan("s.l-o_t g-4.c_0-r").safe
    assert not scanner.scan("s.l.o.t g.4.c.0.r").safe


def test_homoglyph_cyrillic_greek():
    # Cyrillic 'о' (\u043e) and 'а' (\u0430)
    assert normalize("sl\u043et g\u0430cor") == " slot gacor "
    scanner = SafetyScanner()
    assert not scanner.scan("sl\u043et g\u0430cor").safe

    # Greek 'ο' (\u03bf) and 'α' (\u03b1)
    assert normalize("sl\u03bf\u03c4 g\u03b1cor") == " slot gacor "


def test_trailing_twin_digits_evasion():
    assert normalize("g4c0r88") == " gacor 88 "
    assert normalize("jud199") == " judi 99 "
    assert normalize("m4xw1n77") == " maxwin 77 "

    # Dictionary invariant terms must NOT be collapsed
    assert normalize("slot88") == " slot88 "
    assert normalize("4d") == " 4d "
    assert normalize("10k") == " 10k "
    assert normalize("p2p") == " p2p "
    assert normalize("k13") == " k13 "

    scanner = SafetyScanner()
    assert not scanner.scan("m4xw1n77").safe
    assert not scanner.scan("g4c0r88 slot").safe
    assert not scanner.scan("daftar jud199 slot online").safe


def test_nik_with_zero_width_chars_redacted_cleanly():
    # NIK with zero-width space and WhatsApp bidi formatting characters
    raw = "Data NIK: 3171\u200b0115\u202a0190\u202c0001 selesai"
    matches = detect_pii(raw)
    assert len(matches) == 1
    assert matches[0].entity == "ID_NIK"
    assert matches[0].text == "3171\u200b0115\u202a0190\u202c0001"
    assert raw[matches[0].start : matches[0].end] == matches[0].text

    eng = KawalLMEngine()
    masked = eng.mask(raw)
    assert masked.text == "Data NIK: <ID_NIK> selesai"

    # WhatsApp phone number copy-paste with bidi characters \u202a and \u202c inserted inside
    phone_raw = "HP saya +62\u202a812-3456\u202c7890 ya"
    phone_matches = detect_pii(phone_raw)
    assert len(phone_matches) == 1
    assert phone_matches[0].entity == "ID_PHONE"
    assert phone_raw[phone_matches[0].start : phone_matches[0].end] == phone_matches[0].text
    assert eng.mask(phone_raw).text == "HP saya <ID_PHONE> ya"

    # Additional bidi chars (\u2066, \u2069) inserted inside
    bidi_raw = "KTP 3171\u206601150190\u20690001 terverifikasi"
    bidi_matches = detect_pii(bidi_raw)
    assert len(bidi_matches) == 1
    assert bidi_matches[0].entity == "ID_NIK"
    assert eng.mask(bidi_raw).text == "KTP <ID_NIK> terverifikasi"


def test_passport_two_letter_series():
    # 1 letter (classic) and 2 letters (new series)
    assert [m.text for m in find_passport("paspor A 1234567")] == ["A 1234567"]
    assert [m.text for m in find_passport("paspor AA 1234567")] == ["AA 1234567"]
    assert [m.text for m in find_passport("paspor XD1234567")] == ["XD1234567"]

    # Invalid: 3 letters or 8 digits
    assert find_passport("paspor AAA 1234567") == []
    assert find_passport("paspor XD12345678") == []


def test_new_bank_accounts():
    assert [m.meta["bank"] for m in find_bank_account("transfer ke blu 123456789012 ya")] == ["blu"]
    assert [m.meta["bank"] for m in find_bank_account("transfer ke bca digital 123456789012 ya")] == ["bca digital"]
    assert [m.meta["bank"] for m in find_bank_account("rekening muamalat 1234567890")] == ["muamalat"]
    assert [m.meta["bank"] for m in find_bank_account("rekening bjb 1234567890123")] == ["bjb"]
    assert [m.meta["bank"] for m in find_bank_account("rekening bank dki 12345678901")] == ["bank dki"]
    assert [m.meta["bank"] for m in find_bank_account("rekening bank dki 123456789012")] == ["bank dki"]
    assert [m.meta["bank"] for m in find_bank_account("rekening bank jatim 1234567890")] == ["bank jatim"]


def test_fastapi_system_message_and_multimodal():
    pytest.importorskip("fastapi")
    from fastapi import FastAPI, Request
    from fastapi.testclient import TestClient

    from kawallm.integrations.fastapi import KawalLMMiddleware

    # App 1: default scan_system_messages=False
    app1 = FastAPI()
    app1.add_middleware(KawalLMMiddleware, paths=("/chat",))

    @app1.post("/chat")
    async def chat1(req: Request):
        return await req.json()

    c1 = TestClient(app1)

    # System message containing safety keywords is ignored for safety by default, but PII is still masked
    res = c1.post(
        "/chat",
        json={
            "messages": [
                {
                    "role": "system",
                    "content": "You are an assistant for 081234567890. Never promote slot gacor maxwin depo pulsa.",
                },
                {"role": "user", "content": "halo apa kabar"},
            ]
        },
    )
    assert res.status_code == 200
    assert "slot gacor" in res.json()["messages"][0]["content"]
    assert "<ID_PHONE>" in res.json()["messages"][0]["content"]

    # Multimodal split PII across parts must be masked
    res_split_pii = c1.post(
        "/chat",
        json={
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "NIK 31710115"},
                        {"type": "text", "text": "01900001 selesai"},
                        {"type": "image_url", "image_url": {"url": "https://example.com/ktp.png"}},
                    ],
                }
            ]
        },
    )
    assert res_split_pii.status_code == 200
    parts_out = res_split_pii.json()["messages"][0]["content"]
    assert parts_out[0]["text"] == "NIK <ID_NIK>"
    assert parts_out[1]["text"] == " selesai"

    # Single-part multimodal PII masking works even when "text" is not in custom fields
    app_custom = FastAPI()
    app_custom.add_middleware(KawalLMMiddleware, paths=("/chat",), fields=("prompt",))

    @app_custom.post("/chat")
    async def chat_custom(req: Request):
        return await req.json()

    c_custom = TestClient(app_custom)
    res_single_part = c_custom.post(
        "/chat",
        json={
            "messages": [
                {
                    "role": "user",
                    "content": [{"type": "text", "text": "HP 081234567890"}],
                }
            ]
        },
    )
    assert res_single_part.status_code == 200
    assert res_single_part.json()["messages"][0]["content"][0]["text"] == "HP <ID_PHONE>"

    # Multimodal split prompt injection across parts must be blocked
    res_multi = c1.post(
        "/chat",
        json={
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "slot "},
                        {"type": "text", "text": "gacor maxwin depo pulsa"},
                    ],
                }
            ]
        },
    )
    assert res_multi.status_code == 400
    assert "JUDOL_PINJOL" in res_multi.json()["error"]

    # App 2: scan_system_messages=True
    app2 = FastAPI()
    app2.add_middleware(KawalLMMiddleware, paths=("/chat",), scan_system_messages=True)

    @app2.post("/chat")
    async def chat2(req: Request):
        return await req.json()

    c2 = TestClient(app2)
    res_sys_block = c2.post(
        "/chat",
        json={
            "messages": [
                {"role": "system", "content": "slot gacor maxwin depo pulsa"},
            ]
        },
    )
    assert res_sys_block.status_code == 400
    assert "JUDOL_PINJOL" in res_sys_block.json()["error"]
