"""Explicit, offline breach eval. Missing integration dependencies must fail collection, not skip."""

import json
from pathlib import Path
from types import SimpleNamespace as NS

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel

from kawallm import KawalLM
from kawallm import synthetic as syn
from kawallm.integrations.fastapi import KawalLMMiddleware
from kawallm.integrations.litellm import KawalLMGuardrail

CASES = json.loads(Path(__file__).with_name("cases.json").read_text(encoding="utf-8"))
NIK, NIK2, PHONE = syn.nik(701), syn.nik(702), syn.phone(703)
SIZES = (1, 7, 63, 64, 65, 257)


def guard(**kwargs):
    return KawalLMGuardrail(guardrail_name="breach-eval", event_hook=["pre_call", "post_call"], **kwargs)


def response(text=None, arguments=None):
    calls = [NS(function=NS(arguments=arguments))] if arguments is not None else None
    return NS(choices=[NS(message=NS(content=text, tool_calls=calls))])


def chunk(text=None, finish=None, calls=None, legacy=None):
    return NS(
        choices=[NS(index=0, finish_reason=finish, delta=NS(content=text, tool_calls=calls, function_call=legacy))]
    )


class Prompt(BaseModel):
    prompt: str


@pytest.fixture
def client():
    events = []
    app = FastAPI()
    app.add_middleware(KawalLMMiddleware, paths=("/chat",), audit=events.append)

    @app.post("/chat")
    async def chat(payload: Prompt):
        return {"prompt": payload.prompt}

    with TestClient(app) as c:
        yield c, events


@pytest.mark.parametrize("case", CASES["safety"], ids=lambda c: c["id"])
def test_safety_and_benign_controls(case):
    assert KawalLM().scan(case["text"]).is_blocked is case["blocked"]


@pytest.mark.parametrize("variant", ("plain", "zero-width", "bidi", "fullwidth"))
def test_pii_001_unicode_evasion(variant):
    value = NIK
    if variant == "zero-width":
        value = "\u200b".join(value)
    elif variant == "bidi":
        value = value[:8] + "\u202a" + value[8:] + "\u202c"
    elif variant == "fullwidth":
        value = value.translate(str.maketrans("0123456789", "０１２３４５６７８９"))
    out = KawalLM().mask_pii("NIK " + value)
    assert out.replace("\u202c", "") == "NIK <ID_NIK>"


@pytest.mark.parametrize("media", ("application/json", "application/vnd.api+json", "Application/JSON; charset=utf-8"))
@pytest.mark.parametrize("blocked", (False, True))
def test_http_001_media_types(client, media, blocked):
    c, _ = client
    text = "slot gacor maxwin" if blocked else "NIK " + NIK
    r = c.post("/chat", content=json.dumps({"prompt": text}), headers={"content-type": media})
    assert r.status_code == (400 if blocked else 200)
    if not blocked:
        assert r.json() == {"prompt": "NIK <ID_NIK>"}


def test_http_002_untrusted_role(client):
    c, _ = client
    assert c.post("/chat", json={"role": "system", "prompt": "slot gacor maxwin"}).status_code == 400


@pytest.mark.parametrize("surrogate", ("\ud800", "\udfff"))
def test_http_003_encoding_must_not_forward_original(client, surrogate):
    c, events = client
    r = c.post(
        "/chat",
        content=json.dumps({"prompt": "NIK " + NIK, "extra": surrogate}),
        headers={"content-type": "application/json"},
    )
    assert r.status_code == 200
    assert r.json() == {"prompt": "NIK <ID_NIK>"}
    assert events[-1].action == "masked"
    assert NIK not in events[-1].to_json()


@pytest.mark.parametrize("parts", ([NIK[:8], NIK[8:]], [NIK, NIK2]), ids=("split-value", "adjacent-values"))
async def test_parts_001_masking(parts):
    g = guard()
    data = {"messages": [{"role": "user", "content": [{"type": "text", "text": p} for p in parts]}]}
    await g.async_pre_call_hook(None, None, data, "completion")
    out = "".join(p["text"] for p in data["messages"][0]["content"])
    assert out == "<ID_NIK>" * (2 if parts == [NIK, NIK2] else 1)


@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize(
    "text,expected",
    [
        ("NIK " + NIK, "NIK <ID_NIK>"),
        ("paspor A 1234567 " + "x" * 56, "paspor <ID_PASSPORT> " + "x" * 56),
        ("plat B 1234 ABC " + "x" * 56, "plat <ID_PLATE> " + "x" * 56),
        ("rekening 1234567890 sekarang", "rekening <ID_BANK_ACCOUNT> sekarang"),
    ],
    ids=("nik", "passport", "plate", "bank-context"),
)
async def test_stream_001_boundaries_and_finish(size, text, expected):
    g = guard()

    async def source():
        for i in range(0, len(text), size):
            yield chunk(text[i : i + size])
        yield chunk(finish="stop")
        yield NS(choices=[])

    output, finished = "", False
    async for c in g.async_post_call_streaming_iterator_hook(None, source(), {}):
        for choice in c.choices:
            part = choice.delta.content or ""
            assert not (finished and part), "text emitted after finish_reason"
            output += part
            if choice.finish_reason:
                assert output == expected, "incomplete or leaked text at finish_reason"
                finished = True
    assert finished and output == expected


@pytest.mark.parametrize("legacy", (False, True), ids=("tool_calls", "function_call"))
@pytest.mark.parametrize("size", (1, 7, 64))
async def test_tool_001_streamed_arguments(legacy, size):
    raw = json.dumps({"nik": NIK, "note": "synthetic"})
    g = guard()

    async def source():
        for i in range(0, len(raw), size):
            fn = NS(name="lookup" if i == 0 else None, arguments=raw[i : i + size])
            yield chunk(legacy=fn) if legacy else chunk(calls=[NS(index=0, function=fn)])
        yield chunk(finish="stop")
        yield NS(choices=[])

    out = ""
    async for c in g.async_post_call_streaming_iterator_hook(None, source(), {}):
        for choice in c.choices:
            delta = choice.delta
            functions = [delta.function_call] if legacy else [tc.function for tc in delta.tool_calls or []]
            out += "".join(fn.arguments or "" for fn in functions if fn)
            if choice.finish_reason:
                assert json.loads(out) == {"nik": "<ID_NIK>", "note": "synthetic"}
    assert json.loads(out) == {"nik": "<ID_NIK>", "note": "synthetic"}


async def test_tool_002_restore_escaping_and_new_output_pii():
    phone = PHONE[:4] + "\n" + PHONE[4:]
    g = guard(masking_mode="reversible")
    data = {"messages": [{"role": "user", "content": phone}]}
    await g.async_pre_call_hook(None, None, data, "completion")
    tok = data["messages"][0]["content"]
    assert tok.startswith("<ID_PHONE_")
    out = await g.async_post_call_success_hook(data, None, response(arguments=json.dumps({"own": tok, "new": NIK})))
    args = out.choices[0].message.tool_calls[0].function.arguments
    assert json.loads(args) == {"own": phone, "new": "<ID_NIK>"}


async def test_session_001_cross_caller_isolation():
    g = guard(masking_mode="reversible")
    a, b = NS(api_key="synthetic-a"), NS(api_key="synthetic-b")
    first = {"litellm_call_id": "shared", "messages": [{"role": "user", "content": NIK}]}
    await g.async_pre_call_hook(a, None, first, "completion")
    token = first["messages"][0]["content"]
    second = {
        "litellm_call_id": "shared",
        "metadata": {"kawallm_session": "shared"},
        "messages": [{"role": "user", "content": NIK2}],
    }
    await g.async_pre_call_hook(b, None, second, "completion")
    other = await g.async_post_call_success_hook(second, b, response(token))
    own = await g.async_post_call_success_hook(first, a, response(token))
    assert other.choices[0].message.content == token
    assert own.choices[0].message.content == NIK


@pytest.mark.parametrize("size", SIZES)
def test_restore_001_standalone_geo(size):
    g = KawalLM(entities="extended", mode="reversible")
    text = "GPS -6.20000, 106.80000"
    r = g.mask(text)
    assert "<GEO_COORDINATES_" in r.text
    assert g.unmask(r.text, r.session_id) == text
    stream = g.unmask_stream(r.session_id)
    assert "".join(stream.feed(r.text[i : i + size]) for i in range(0, len(r.text), size)) + stream.flush() == text


@pytest.mark.parametrize("case", CASES["address"], ids=lambda c: c["id"])
def test_address_generalization(case):
    assert KawalLM(entities="extended", mode="generalize").mask_pii(case["text"]) == case["expected"]


@pytest.mark.parametrize("text", ("BPJS " + syn.bpjs_kesehatan(704), "KPJ " + syn.digits(11, 705)))
def test_config_001_bpjs_alias(text):
    g = KawalLM(mode="reversible", mode_by_entity={"ID_BPJS": "redact"})
    r = g.mask(text)
    assert r.text == text.split()[0] + " [REDACTED]"
    assert g.unmask(r.text, r.session_id) == r.text
