"""Regression tests for the fourth review: keyword distance in streams, thinking blocks in streams and requests,
exponent expansion, and exact number text in tool-call arguments."""

import json
from types import SimpleNamespace as NS

import pytest

from kawallm import KawalLM

NIK = "3171011501900001"


def _guard(**kw):
    pytest.importorskip("litellm")
    from kawallm.integrations.litellm import KawalLMGuardrail

    return KawalLMGuardrail(guardrail_name="k", event_hook=["pre_call", "post_call"], **kw)


def _refuse(name):
    """Standard JSON has no NaN or Infinity: refuse them when parsing."""
    raise ValueError(name)


async def _stream_content(g, text, size):
    async def gen():
        for i in range(0, len(text), size):
            yield NS(choices=[NS(index=0, finish_reason=None, delta=NS(content=text[i : i + size], tool_calls=None))])

    out = ""
    async for c in g.async_post_call_streaming_iterator_hook(None, gen(), {}):
        for x in c.choices:
            out += getattr(x.delta, "content", None) or ""
    return out


# ---------------------------------------------------------------- 1. keyword far after a number, any chunking
# The bank detector reads 120 characters around a number, so 110 is the largest distance it can ever link.
@pytest.mark.parametrize("distance", [0, 30, 60, 90, 110])
@pytest.mark.parametrize("size", [1, 7, 65])
async def test_bank_keyword_after_the_number_is_seen_for_every_distance_and_chunking(distance, size):
    text = f"1234567890 untuk {' ' * distance}rekening BCA selesai " + "x " * 60
    out = await _stream_content(_guard(), text, size)
    assert "1234567890" not in out
    assert out == KawalLM().scan(text).sanitized_text


# ---------------------------------------------------------------- 2. thinking blocks in a stream
async def _stream_thinking(g, text, size, signature_at_end=True):
    types = pytest.importorskip("litellm.types.utils")

    async def gen():
        for i in range(0, len(text), size):
            block = {"type": "thinking", "thinking": text[i : i + size], "signature": None}
            delta = types.Delta(content=None, thinking_blocks=[block])
            yield types.ModelResponseStream(choices=[types.StreamingChoices(index=0, delta=delta)])
        if signature_at_end:
            block = {"type": "thinking", "thinking": "", "signature": "sig-abc"}
            delta = types.Delta(content=None, thinking_blocks=[block])
            yield types.ModelResponseStream(choices=[types.StreamingChoices(index=0, delta=delta)])
        yield types.ModelResponseStream(
            choices=[types.StreamingChoices(index=0, finish_reason="stop", delta=types.Delta(content=None))]
        )

    thinking, signatures = "", []
    async for c in g.async_post_call_streaming_iterator_hook(None, gen(), {}):
        for block in getattr(c.choices[0].delta, "thinking_blocks", None) or []:
            thinking += block.get("thinking") or ""
            if block.get("signature"):
                signatures.append(block["signature"])
    return thinking, signatures


@pytest.mark.parametrize("size", [1, 5, 13])
async def test_thinking_block_text_is_masked_in_a_stream(size):
    text = f"Pikir: NIK {NIK} lalu rekening BCA 1234567890 selesai " + "x " * 40
    thinking, signatures = await _stream_thinking(_guard(), text, size)
    assert NIK not in thinking and "1234567890" not in thinking
    assert thinking == KawalLM().scan(text).sanitized_text
    assert signatures == ["sig-abc"]  # the signature is passed through unchanged


# ---------------------------------------------------------------- 3. thinking and reasoning sent back in history
async def _pre(g, message):
    d = {"messages": [message, {"role": "user", "content": "lanjut"}]}
    await g.async_pre_call_hook(None, None, d, "completion")
    return d["messages"][0]


async def test_reasoning_content_in_history_is_masked_before_the_provider_sees_it():
    msg = await _pre(_guard(), {"role": "assistant", "content": "ok", "reasoning_content": f"NIK {NIK}"})
    assert msg["reasoning_content"] == "NIK <ID_NIK>" and msg["content"] == "ok"


async def test_unsigned_thinking_block_in_history_is_masked_in_place():
    msg = await _pre(
        _guard(),
        {"role": "assistant", "content": "ok", "thinking_blocks": [{"type": "thinking", "thinking": f"NIK {NIK}"}]},
    )
    assert msg["thinking_blocks"] == [{"type": "thinking", "thinking": "NIK <ID_NIK>"}]


async def test_signed_thinking_block_with_pii_is_dropped_and_a_clean_one_is_kept():
    clean = {"type": "thinking", "thinking": "hitung dulu", "signature": "sig-1"}
    dirty = {"type": "thinking", "thinking": f"NIK {NIK}", "signature": "sig-2"}
    msg = await _pre(_guard(), {"role": "assistant", "content": "ok", "thinking_blocks": [clean, dirty]})
    assert msg["thinking_blocks"] == [clean]  # changing a signed text would make the provider reject it


async def test_thinking_part_in_a_content_list_is_masked_too():
    part = {"type": "thinking", "thinking": f"NIK {NIK}"}
    msg = await _pre(_guard(), {"role": "assistant", "content": [part, {"type": "text", "text": "ok"}]})
    assert msg["content"] == [{"type": "thinking", "thinking": "NIK <ID_NIK>"}, {"type": "text", "text": "ok"}]


# ---------------------------------------------------------------- 4. numbers in tool-call arguments
async def _args(g, args):
    d = {"messages": [{"role": "assistant", "content": None, "tool_calls": [{"function": {"arguments": args}}]}]}
    await g.async_pre_call_hook(None, None, d, "completion")
    return d["messages"][0]["tool_calls"][0]["function"]["arguments"]


async def test_a_huge_exponent_is_refused_without_expanding_it():
    with pytest.raises(Exception) as info:
        await _args(_guard(), '{"n":1e100000}')
    assert info.value.status_code == 400


async def test_an_unrelated_float_keeps_its_text_when_a_field_is_masked():
    out = await _args(_guard(), f'{{"amount":1e400,"nik":"{NIK}"}}')
    assert '"amount": 1e400' in out  # the original text, not 1E+400 or Infinity
    assert json.loads(out, parse_constant=_refuse) == json.loads('{"amount":1e400,"nik":"<ID_NIK>"}')


async def test_long_decimal_keeps_its_precision():
    out = await _args(_guard(), f'{{"x":1.2345678901234567890123,"nik":"{NIK}"}}')
    assert '"x": 1.2345678901234567890123' in out


async def test_nan_in_arguments_is_not_rewritten_into_invalid_json():
    out = await _args(_guard(), f'{{"x":NaN,"nik":"{NIK}"}}')
    assert NIK not in out  # still masked as plain text, and the input's own NaN is not turned into Infinity
    assert "Infinity" not in out
