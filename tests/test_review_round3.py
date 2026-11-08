"""Regression tests for the third review: candidate selection, stream context, extra response fields, JSON
representations, overlaps, audit path, vault lifecycle, and the smaller consistency items."""

import json
import time
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

from kawallm import KawalLM, KawalLMEngine
from kawallm.__main__ import main

NIK = "3171011501900001"
ROOT = Path(__file__).resolve().parents[1]


def _guard(**kw):
    pytest.importorskip("litellm")
    from kawallm.integrations.litellm import KawalLMGuardrail

    return KawalLMGuardrail(guardrail_name="k", event_hook=["pre_call", "post_call"], **kw)


# ---------------------------------------------------------------- 1. extra digits next to a valid number
@pytest.mark.parametrize(
    "text,expected",
    [
        ("HP 081234567890", "HP <ID_PHONE>"),
        ("HP 081234567890 25 November", "HP <ID_PHONE> 25 November"),
        ("HP 081234567890, antrean 12345", "HP <ID_PHONE>, antrean 12345"),
        ("HP 081234567890 dan 6 orang", "HP <ID_PHONE> dan 6 orang"),
        ("HP 0812 3456 7890 25", "HP <ID_PHONE> 25"),
        ("Telp 021-5551234 25 orang", "Telp <ID_PHONE> 25 orang"),
        ("rekening BCA 1234567890 1000000", "rekening BCA <ID_BANK_ACCOUNT> 1000000"),
        ("rekening BCA 1000000 1234567890", "rekening BCA 1000000 <ID_BANK_ACCOUNT>"),
        ("rekening BCA 1234567890 pada 25 11 2026", "rekening BCA <ID_BANK_ACCOUNT> pada 25 11 2026"),
        ("kontak +62 812 3456 7890 25", "kontak <ID_PHONE> 25"),
    ],
)
def test_valid_number_is_found_next_to_other_numbers(text, expected):
    assert KawalLM().scan(text).sanitized_text == expected


@pytest.mark.parametrize("text", ["total 081234567890123456789 rupiah", "kode 1234 5678 9012 3456 7890 1234"])
def test_a_long_unrelated_digit_run_is_still_left_alone(text):
    assert KawalLM().scan(text).sanitized_text == text


# ---------------------------------------------------------------- 2. stream == non-stream
async def _stream_text(g, text, size):
    async def gen():
        for i in range(0, len(text), size):
            yield NS(choices=[NS(index=0, finish_reason=None, delta=NS(content=text[i : i + size], tool_calls=None))])

    out = ""
    async for c in g.async_post_call_streaming_iterator_hook(None, gen(), {}):
        for x in c.choices:
            out += getattr(x.delta, "content", None) or ""
    return out


@pytest.mark.parametrize(
    "text",
    [
        "1234567890 untuk rekening BCA " + "x" * 52,
        "Nomor 081234567890 25 November " + "y " * 40,
        "NIK " + NIK + " " + "z " * 40,
        "id budi@contoh.co.id " + "w" * 70,
        "paspor A 1234567 " + "x" * 56,
        "Plat B 1234 ABC " + "x " * 40,
        "tanpa data pribadi sama sekali " * 8,
    ],
)
@pytest.mark.parametrize("size", [1, 3, 7, 13, 50, 64, 65])
async def test_stream_result_equals_non_stream_result_for_every_chunking(text, size):
    g = _guard()
    assert await _stream_text(g, text, size) == KawalLM().scan(text).sanitized_text


# ---------------------------------------------------------------- 3. reasoning_content and other text fields
async def test_reasoning_content_is_masked_in_a_complete_response():
    types = pytest.importorskip("litellm.types.utils")
    g = _guard()
    msg = types.Message(content="halo", reasoning_content=f"NIK {NIK}, HP 081234567890")
    out = await g.async_post_call_success_hook({}, None, types.ModelResponse(choices=[types.Choices(message=msg)]))
    assert out.choices[0].message.reasoning_content == "NIK <ID_NIK>, HP <ID_PHONE>"
    assert out.choices[0].message.content == "halo"


@pytest.mark.parametrize("size", [1, 5, 13])
async def test_reasoning_content_is_masked_in_a_stream_split_anywhere(size):
    types = pytest.importorskip("litellm.types.utils")
    g = _guard()
    text = f"Pikir: NIK {NIK} lalu rekening BCA 1234567890 selesai " + "x " * 40

    async def gen():
        for i in range(0, len(text), size):
            delta = types.Delta(reasoning_content=text[i : i + size], content=None)
            yield types.ModelResponseStream(choices=[types.StreamingChoices(index=0, delta=delta)])
        yield types.ModelResponseStream(
            choices=[types.StreamingChoices(index=0, finish_reason="stop", delta=types.Delta(content=None))]
        )

    got = ""
    async for c in g.async_post_call_streaming_iterator_hook(None, gen(), {}):
        got += getattr(c.choices[0].delta, "reasoning_content", None) or ""
    assert NIK not in got and "1234567890" not in got
    assert got == KawalLM().scan(text).sanitized_text


async def test_content_and_reasoning_streams_do_not_mix_their_buffers():
    types = pytest.importorskip("litellm.types.utils")
    g = _guard()
    steps = [("NIK 31710115", None), (None, "HP 0812"), ("01900001 x", "34567890 ya")]

    async def gen():
        for reasoning, content in steps:
            delta = types.Delta(reasoning_content=reasoning, content=content)
            yield types.ModelResponseStream(choices=[types.StreamingChoices(index=0, delta=delta)])
        yield types.ModelResponseStream(
            choices=[types.StreamingChoices(index=0, finish_reason="stop", delta=types.Delta(content=None))]
        )

    reasoning = content = ""
    async for c in g.async_post_call_streaming_iterator_hook(None, gen(), {}):
        reasoning += getattr(c.choices[0].delta, "reasoning_content", None) or ""
        content += getattr(c.choices[0].delta, "content", None) or ""
    assert reasoning == "NIK <ID_NIK> x" and content == "HP <ID_PHONE> ya"


async def test_thinking_blocks_are_masked_in_a_complete_response():
    g = _guard()
    block = {"type": "thinking", "thinking": f"NIK {NIK}", "signature": "sig"}
    msg = NS(content="ok", tool_calls=None, thinking_blocks=[block])
    out = await g.async_post_call_success_hook({}, None, NS(choices=[NS(message=msg)]))
    assert not out.choices[0].message.thinking_blocks  # changed text: the signed block is not sent


async def test_a_clean_signed_thinking_block_is_kept_as_it_was():
    g = _guard()
    block = {"type": "thinking", "thinking": "hitung dulu", "signature": "sig"}
    msg = NS(content="ok", tool_calls=None, thinking_blocks=[block])
    out = await g.async_post_call_success_hook({}, None, NS(choices=[NS(message=msg)]))
    assert out.choices[0].message.thinking_blocks == [
        {"type": "thinking", "thinking": "hitung dulu", "signature": "sig"}
    ]


# ---------------------------------------------------------------- 4. JSON keys and floats in tool-call arguments
@pytest.mark.parametrize(
    "args,expected",
    [
        ('{"3171011501900001": "x"}', {"<ID_NIK>": "x"}),
        ('{"nik": 3171011501900001.0}', {"nik": "<ID_NIK>"}),
        ('{"nik": 3.171011501900001e15}', {"nik": "<ID_NIK>"}),
        ('{"nik": 3171011501900001}', {"nik": "<ID_NIK>"}),
        ('{"harga": 12.5, "n": 3, "ok": true, "x": null}', {"harga": 12.5, "n": 3, "ok": True, "x": None}),
        ('{"a": "3171011501900001", "3171011501900001": "y"}', {"a": "<ID_NIK>", "<ID_NIK>": "y"}),
        ('{"a": "3171011501900001", "3171011501900001": "y"}'.replace('"a"', '"<ID_NIK>"'), None),
    ],
)
async def test_json_keys_and_floats_are_masked_and_the_arguments_stay_valid(args, expected):
    g = _guard()
    d = {"messages": [{"role": "assistant", "content": None, "tool_calls": [{"function": {"arguments": args}}]}]}
    await g.async_pre_call_hook(None, None, d, "completion")
    out = d["messages"][0]["tool_calls"][0]["function"]["arguments"]
    parsed = json.loads(out)  # always valid JSON
    assert NIK not in out
    if expected is not None:
        assert parsed == expected


# ---------------------------------------------------------------- 5. overlap: a whole e-mail stays protected
@pytest.mark.parametrize(
    "text,expected",
    [
        ("budi.081234567890@example.com", "<EMAIL>"),
        (f"{NIK}@example.com", "<EMAIL>"),
        ("HP 081234567890 dan budi@x.co.id", "HP <ID_PHONE> dan <EMAIL>"),
    ],
)
def test_an_email_is_masked_whole_even_when_digits_inside_look_like_another_entity(text, expected):
    assert KawalLM().scan(text).sanitized_text == expected


# ---------------------------------------------------------------- 6. audit path
def test_audit_context_path_is_masked():
    from fastapi import FastAPI, Request
    from fastapi.testclient import TestClient

    from kawallm.integrations.fastapi import KawalLMMiddleware

    events = []
    app = FastAPI()
    app.add_middleware(KawalLMMiddleware, paths=("/chat",), fields=("prompt",), audit=events.append)

    @app.post("/chat/{ident}")
    async def chat(ident: str, req: Request):
        return {"ok": True}

    TestClient(app).post(f"/chat/{NIK}", json={"prompt": "halo"})
    assert events and events[-1].context["path"] == "/chat/<ID_NIK>"
    assert NIK not in events[-1].to_json()


# ---------------------------------------------------------------- 7. vault lifecycle and cost
def test_expired_sessions_are_removed_when_read():
    e = KawalLMEngine(mode="reversible", vault_ttl=0.02)
    e.mask(f"NIK {NIK}", "s1")
    time.sleep(0.05)
    assert e.vault.mapping("s1") == {}
    assert not any(NIK in str(v) for v in e.vault._data.values())  # gone from memory, not just hidden


def test_sweep_removes_every_expired_session():
    e = KawalLMEngine(mode="reversible", vault_ttl=0.02)
    for i in range(5):
        e.mask(f"NIK {NIK}", f"s{i}")
    time.sleep(0.05)
    assert e.vault.sweep() == 5 and e.vault._data == {}


def test_reversible_numbering_stays_correct_and_does_not_slow_down_with_many_entities():
    mails = " ".join(f"u{i}@contoh.co.id" for i in range(3000))
    e = KawalLMEngine(mode="reversible")
    started = time.perf_counter()
    r = e.mask(mails)
    assert time.perf_counter() - started < 0.5  # it was about 0.5 s: the cost grew with the square of the count
    tokens = [t for t in r.text.split() if t.startswith("<EMAIL_")]
    assert [int(t.split("_")[1]) for t in tokens] == list(range(1, 3001))
    assert e.unmask(r.text, r.session_id) == mails


# ---------------------------------------------------------------- smaller consistency items
def test_cli_accepts_the_extended_profile_and_generalize(capsys):
    assert main(["--entities", "extended", "--mode", "generalize", "Lahir: 12 Mei 1990, usia 34 tahun"]) == 0
    assert capsys.readouterr().out.strip() == "Lahir: 1990, usia 30-39 tahun"


def test_presidio_profile_selects_the_quasi_identifiers():
    pytest.importorskip("presidio_analyzer")
    from kawallm.integrations.presidio import analyzer_without_nlp

    text = "Tanggal lahir 12 Mei 1990, usia 34 tahun, HP 081234567890"
    core = {r.entity_type for r in analyzer_without_nlp("id").analyze(text, language="id")}
    ext = {r.entity_type for r in analyzer_without_nlp("id", profile="extended").analyze(text, language="id")}
    assert core == {"ID_PHONE"} and ext == {"ID_PHONE", "ID_BIRTHDATE", "ID_AGE"}
    with pytest.raises(ValueError, match="profile"):
        analyzer_without_nlp("id", profile="nope")


def test_compose_has_no_default_master_key_and_release_runs_the_breach_evals():
    compose = (ROOT / "docker" / "docker-compose.yml").read_text(encoding="utf-8")
    assert "sk-change-me" not in compose and "LITELLM_MASTER_KEY:?" in compose
    publish = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
    assert "evals/breaches" in publish
