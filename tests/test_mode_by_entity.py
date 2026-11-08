"""``mode_by_entity``: a different mask mode for individual entities (e.g. phone reversible, NIK token)."""

import json
from types import SimpleNamespace as NS

import pytest
from helpers import shape, token

from kawallm import AuditLog, KawalLM, KawalLMEngine

NIK = "3171011501900001"
PHONE = "081234567890"
MAIL = "budi@contoh.co.id"
TEXT = f"NIK {NIK}, HP {PHONE}, mail {MAIL}"
BY_ENTITY = {"ID_PHONE": "reversible", "EMAIL": "reversible"}


# ---------------------------------------------------------------- engine
def test_only_the_configured_entities_are_reversible():
    e = KawalLMEngine(mode="token", mode_by_entity=BY_ENTITY)
    r = e.mask(TEXT)
    assert shape(r.text) == "NIK <ID_NIK>, HP <ID_PHONE_1>, mail <EMAIL_1>"
    assert e.unmask(r.text, r.session_id) == f"NIK <ID_NIK>, HP {PHONE}, mail {MAIL}"  # the NIK stays masked


def test_entity_mode_overrides_the_engine_mode_both_ways():
    e = KawalLMEngine(mode="reversible", mode_by_entity={"ID_NIK": "token", "ID_PHONE": "redact"})
    r = e.mask(TEXT)
    assert "<ID_NIK>" in r.text and "[REDACTED]" in r.text and shape(r.text).count("<EMAIL_1>") == 1
    assert e.unmask(r.text, r.session_id) == f"NIK <ID_NIK>, HP [REDACTED], mail {MAIL}"


def test_an_explicit_mode_in_the_call_applies_to_every_entity():
    e = KawalLMEngine(mode="token", mode_by_entity=BY_ENTITY)
    assert e.mask(TEXT, mode="token").text == "NIK <ID_NIK>, HP <ID_PHONE>, mail <EMAIL>"
    assert e.mask_pii(TEXT, mode="redact") == "NIK [REDACTED], HP [REDACTED], mail [REDACTED]"


def test_no_mapping_behaves_exactly_as_before():
    plain = KawalLMEngine(mode="token")
    assert plain.mode_by_entity == {} and not plain.reversible_enabled
    assert plain.mask(TEXT).text == "NIK <ID_NIK>, HP <ID_PHONE>, mail <EMAIL>"
    assert plain.mask(TEXT).session_id is None


def test_session_id_is_returned_when_any_entity_is_reversible():
    e = KawalLMEngine(mode="token", mode_by_entity=BY_ENTITY)
    assert e.reversible_enabled
    assert e.mask("halo tanpa data").session_id  # so the caller can unmask the model's answer later


def test_generalize_per_entity_with_the_extended_profile():
    e = KawalLMEngine(
        entities="extended", mode="token", mode_by_entity={"ID_BIRTHDATE": "generalize", "ID_PHONE": "reversible"}
    )
    out = e.mask(f"Lahir: 12 Mei 1990, HP {PHONE}, NIK {NIK}").text
    assert out.startswith("Lahir: 1990, HP <ID_PHONE_1_") and out.endswith("NIK <ID_NIK>")


def test_anonymize_keeps_unrestorable_entities_out_of_the_session_map():
    e = KawalLM(mode="token", mode_by_entity={"ID_NIK": "token"})
    text, session_map = e.anonymize(TEXT)
    assert "<ID_NIK>" in text and set(session_map.values()) == {PHONE, MAIL}
    assert e.deanonymize(text, session_map) == f"NIK <ID_NIK>, HP {PHONE}, mail {MAIL}"


def test_scan_and_audit_work_with_a_mapping():
    events = []
    guard = KawalLM(mode_by_entity=BY_ENTITY, audit=AuditLog(events.append))
    r = guard.scan(TEXT)
    assert r.session_id and NIK not in r.sanitized_text
    assert events[0].entities == {"EMAIL": 1, "ID_NIK": 1, "ID_PHONE": 1}


@pytest.mark.parametrize(
    "mapping,message",
    [
        ({"ID_NOPE": "token"}, "unknown entity"),
        ({"ID_PHONE": "encrypt"}, "must be one of"),
    ],
)
def test_bad_mapping_fails_at_construction(mapping, message):
    with pytest.raises(ValueError, match=message):
        KawalLMEngine(mode_by_entity=mapping)


# ---------------------------------------------------------------- LiteLLM
def _guard(**kw):
    pytest.importorskip("litellm")
    from kawallm.integrations.litellm import KawalLMGuardrail

    return KawalLMGuardrail(guardrail_name="k", event_hook=["pre_call", "post_call"], **kw)


def _response(text, args=None):
    calls = [NS(function=NS(arguments=args))] if args else None
    return NS(choices=[NS(message=NS(content=text, tool_calls=calls))])


async def test_litellm_restores_only_the_reversible_entities():
    g = _guard(masking_mode="token", mode_by_entity=BY_ENTITY)
    d = {"litellm_call_id": "m1", "messages": [{"role": "user", "content": TEXT}]}
    await g.async_pre_call_hook(None, None, d, "completion")
    sent = d["messages"][0]["content"]
    assert NIK not in sent and PHONE not in sent and MAIL not in sent and "<ID_NIK>" in sent
    phone_tok = token(sent, "<ID_PHONE_1>")
    reply = _response(f"Hubungi {phone_tok}, NIK <ID_NIK>", args=json.dumps({"hp": phone_tok, "nik": "<ID_NIK>"}))
    out = await g.async_post_call_success_hook(d, None, reply)
    msg = out.choices[0].message
    assert msg.content == f"Hubungi {PHONE}, NIK <ID_NIK>"
    assert json.loads(msg.tool_calls[0].function.arguments) == {"hp": PHONE, "nik": "<ID_NIK>"}


async def test_litellm_without_a_mapping_in_token_mode_restores_nothing():
    g = _guard(masking_mode="token")
    d = {"litellm_call_id": "m2", "messages": [{"role": "user", "content": TEXT}]}
    await g.async_pre_call_hook(None, None, d, "completion")
    assert "<ID_PHONE>" in d["messages"][0]["content"]
    assert "kawallm_session" not in d.get("metadata", {})  # no reversible entity: no session is created


def test_litellm_mapping_from_yaml_dict_and_from_a_string():
    assert _guard(mode_by_entity={"ID_PHONE": "reversible"}).engine.mode_by_entity == {"ID_PHONE": "reversible"}
    g = _guard(mode_by_entity="ID_PHONE=reversible, EMAIL=redact")
    assert g.engine.mode_by_entity == {"ID_PHONE": "reversible", "EMAIL": "redact"}
    with pytest.raises(ValueError, match="must look like"):
        _guard(mode_by_entity="ID_PHONE")


async def test_litellm_split_parts_use_the_per_entity_mode():
    g = _guard(masking_mode="token", mode_by_entity=BY_ENTITY)
    parts = ["HP 08123456", "7890 dan NIK ", NIK]
    d = {
        "litellm_call_id": "m3",
        "messages": [{"role": "user", "content": [{"type": "text", "text": t} for t in parts]}],
    }
    await g.async_pre_call_hook(None, None, d, "completion")
    out = "".join(p["text"] for p in d["messages"][0]["content"])
    assert shape(out) == "HP <ID_PHONE_1> dan NIK <ID_NIK>"


# ---------------------------------------------------------------- FastAPI: two complete values in adjacent parts
def test_fastapi_masks_two_complete_values_in_adjacent_parts():
    from collections import Counter

    from kawallm.integrations.fastapi import KawalLMMiddleware

    m = KawalLMMiddleware(app=None)
    body = {
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": NIK}, {"type": "text", "text": "3171015501920002"}]}
        ]
    }
    out = m._walk(body, Counter(), [False])
    assert [p["text"] for p in out["messages"][0]["content"]] == ["<ID_NIK>", "<ID_NIK>"]


def test_detector_key_applies_to_every_entity_it_emits():
    e = KawalLMEngine(mode="reversible", mode_by_entity={"ID_BPJS": "redact"})
    assert e.mode_by_entity == {"ID_BPJS_KES": "redact", "ID_BPJS_TK": "redact"}
    r = e.mask("BPJS 0001234567890")
    assert r.text == "BPJS [REDACTED]"
    assert e.unmask(r.text, r.session_id) == "BPJS [REDACTED]"  # the number cannot be restored


def test_an_entry_for_the_entity_itself_wins_over_its_detector_key():
    e = KawalLMEngine(mode="reversible", mode_by_entity={"ID_BPJS": "redact", "ID_BPJS_TK": "token"})
    assert e.mode_by_entity == {"ID_BPJS_KES": "redact", "ID_BPJS_TK": "token"}
    e2 = KawalLMEngine(mode="reversible", mode_by_entity={"ID_BPJS_TK": "token", "ID_BPJS": "redact"})
    assert e2.mode_by_entity == {"ID_BPJS_KES": "redact", "ID_BPJS_TK": "token"}  # order does not matter
