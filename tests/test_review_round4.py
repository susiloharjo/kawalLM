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
    assert signatures == []  # the text changed, so the original signature is not sent with it


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


# ---------------------------------------------------------------- 5. stream thinking, checked with LiteLLM's assembler
def _thinking_chunk(blocks, finish=None):
    types = pytest.importorskip("litellm.types.utils")
    delta = types.Delta(content=None, thinking_blocks=blocks)
    return types.ModelResponseStream(choices=[types.StreamingChoices(index=0, finish_reason=finish, delta=delta)])


async def _assembled_thinking(g, inputs):
    """Run the stream through the guardrail, then rebuild the message the way LiteLLM does for a client."""
    pytest.importorskip("litellm")
    from litellm.litellm_core_utils.streaming_chunk_builder_utils import ChunkProcessor

    async def gen():
        for c in inputs:
            yield c

    emitted = [c.model_dump() async for c in g.async_post_call_streaming_iterator_hook(None, gen(), {})]
    return ChunkProcessor(emitted).get_combined_thinking_content(emitted)


async def _stream_by_index(g, inputs):
    """Concatenated thinking text per block index, as a client sees it."""
    texts: dict = {}
    async for c in g.async_post_call_streaming_iterator_hook(None, _as_gen(inputs), {}):
        for b in getattr(c.choices[0].delta, "thinking_blocks", None) or []:
            texts[b.get("index")] = texts.get(b.get("index"), "") + (b.get("thinking") or "")
    return texts


async def _as_gen(items):
    for item in items:
        yield item


async def test_two_thinking_blocks_with_the_same_number_are_masked_separately():
    inputs = [
        _thinking_chunk([{"type": "thinking", "thinking": f"NIK {NIK}", "signature": None, "index": 0}]),
        _thinking_chunk([{"type": "thinking", "thinking": "", "signature": "sig-a", "index": 0}]),
        _thinking_chunk([{"type": "thinking", "thinking": f"NIK {NIK}", "signature": None, "index": 1}]),
        _thinking_chunk([{"type": "thinking", "thinking": "", "signature": "sig-b", "index": 1}]),
        _thinking_chunk([], "stop"),
    ]
    assert await _stream_by_index(_guard(), inputs) == {0: "NIK <ID_NIK>", 1: "NIK <ID_NIK>"}


@pytest.mark.parametrize("size", [1, 4, 9])
async def test_a_signed_block_whose_text_changed_is_not_sent_as_a_reusable_block(size):
    text = f"Pikir: NIK {NIK} lalu rekening BCA 1234567890 selesai " + "x " * 20
    inputs = [
        _thinking_chunk([{"type": "thinking", "thinking": text[i : i + size], "signature": None, "index": 0}])
        for i in range(0, len(text), size)
    ]
    inputs.append(_thinking_chunk([{"type": "thinking", "thinking": "", "signature": "sig-x", "index": 0}]))
    inputs.append(_thinking_chunk([], "stop"))
    assert await _stream_by_index(_guard(), inputs) == {0: KawalLM().scan(text).sanitized_text}
    assert not await _assembled_thinking(_guard(), inputs)  # no block carries sig-x with masked text


async def test_masked_signed_thinking_is_not_reused_with_its_original_signature_in_the_next_request():
    inputs = [
        _thinking_chunk([{"type": "thinking", "thinking": f"NIK {NIK}", "signature": None, "index": 0}]),
        _thinking_chunk([{"type": "thinking", "thinking": "", "signature": "orig-sig", "index": 0}]),
        _thinking_chunk([], "stop"),
    ]
    blocks = await _assembled_thinking(_guard(), inputs)
    history = {
        "messages": [
            {"role": "assistant", "content": "ok", "thinking_blocks": blocks},
            {"role": "user", "content": "lanjut"},
        ]
    }
    await _guard().async_pre_call_hook(None, None, history, "completion")
    sent = history["messages"][0].get("thinking_blocks") or []
    assert all(b.get("signature") != "orig-sig" for b in sent)
    assert NIK not in json.dumps(history)


async def test_signature_arriving_after_clean_text_still_reaches_the_client_with_its_text():
    inputs = [
        _thinking_chunk([{"type": "thinking", "thinking": "hitung dulu", "signature": None, "index": 0}]),
        _thinking_chunk([{"type": "thinking", "thinking": "", "signature": "sig-clean", "index": 0}]),
        _thinking_chunk([], "stop"),
    ]
    blocks = await _assembled_thinking(_guard(), inputs)
    assert blocks == [{"type": "thinking", "thinking": "hitung dulu", "signature": "sig-clean"}]


async def test_unsigned_thinking_text_at_the_end_of_a_stream_is_still_masked():
    inputs = [
        _thinking_chunk([{"type": "thinking", "thinking": f"NIK {NIK}", "signature": None, "index": 0}]),
        _thinking_chunk([], "stop"),
    ]
    g = _guard()

    async def gen():
        for c in inputs:
            yield c

    text = "".join(
        b["thinking"]
        for c in [x async for x in g.async_post_call_streaming_iterator_hook(None, gen(), {})]
        for b in (getattr(c.choices[0].delta, "thinking_blocks", None) or [])
    )
    assert NIK not in text and text == "NIK <ID_NIK>"
