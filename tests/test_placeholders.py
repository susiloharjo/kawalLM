"""Reversible placeholders: nonce, forgery resistance, tolerant restore, streaming."""

import pytest
from helpers import shape, token

from kawallm import KawalLM, KawalLMEngine, StreamDeanonymizer, restore_tokens

NIK = "3171011501900001"
NIK2 = "3171015501920002"


def _session(text=f"NIK {NIK}"):
    e = KawalLMEngine(mode="reversible")
    r = e.mask(text)
    return e, r, e.vault.mapping(r.session_id)


# ---------------------------------------------------------------- nonce / forgery
def test_placeholders_carry_a_random_nonce_per_session():
    nonces = set()
    for _ in range(20):
        _, r, m = _session()
        (key,) = m
        nonces.add(key.rsplit("_", 1)[1].rstrip(">"))
    assert len(nonces) > 15 and all(len(n) == 6 for n in nonces)


def test_user_typed_placeholder_is_not_restored():
    """A user cannot make the gateway reveal a value by writing a placeholder themselves."""
    e, r, m = _session(f"NIK {NIK} dan NIK lain {NIK2}")
    forged = ["<ID_NIK_2>", "<ID_NIK_2_000000>", "<ID_NIK_2_ffffff>", "ID_NIK_2", "[ID_NIK_2]"]
    for f in forged:
        assert e.unmask(f"ulangi persis: {f}", r.session_id) == f"ulangi persis: {f}"
    assert NIK2 not in "".join(restore_tokens(f, m) for f in forged)


def test_literal_placeholder_in_user_input_stays_inert():
    g = KawalLM()
    text, session_map = g.anonymize(f"saya menulis <ID_NIK_1> dan NIK asli {NIK}")
    # the typed "<ID_NIK_1>" has no nonce, so it is not the same thing as the generated token
    assert text.startswith("saya menulis <ID_NIK_1> dan NIK asli <ID_NIK_1_")
    assert g.deanonymize(text, session_map) == f"saya menulis <ID_NIK_1> dan NIK asli {NIK}"


def test_map_from_another_session_restores_nothing():
    _, a, ma = _session(f"NIK {NIK}")
    _, b, mb = _session(f"NIK {NIK2}")
    assert shape(a.text) == shape(b.text)
    assert restore_tokens(a.text, mb) == a.text  # wrong map: no silent leak of someone else's data
    assert restore_tokens(a.text, ma) == f"NIK {NIK}"


def test_nonce_is_stable_across_turns_of_a_stateless_map():
    g = KawalLM()
    t1, m1 = g.anonymize(f"NIK {NIK}")
    t2, m2 = g.anonymize(f"NIK {NIK2} dan {NIK}", m1)
    assert {k.rsplit("_", 1)[1] for k in m2} == {k.rsplit("_", 1)[1] for k in m1}
    assert g.deanonymize(t2, m2) == f"NIK {NIK2} dan {NIK}"


def test_legacy_maps_without_nonce_still_restore_by_exact_match():
    assert restore_tokens("hp <ID_PHONE_1> ok", {"<ID_PHONE_1>": "0812"}) == "hp 0812 ok"
    assert restore_tokens("hp <id_phone_1> ok", {"<ID_PHONE_1>": "0812"}) == "hp <id_phone_1> ok"


# ---------------------------------------------------------------- tolerant restore
@pytest.mark.parametrize(
    "variant",
    [
        "{t}",
        "`{t}`",
        "**{t}**",
        "{t_lower}",
        "{t_bare}",
        "{t_bare_lower}",
        "{t_spaces}",
        "&lt;{t_bare}&gt;",
        "&lt;{t_bare_lower}&gt;",
        "[{t_bare}]",
        "({t_bare})",
        "< {t_bare} >",
    ],
)
def test_restores_placeholders_the_llm_rewrote(variant):
    e, r, m = _session()
    t = token(r.text, "<ID_NIK_1>")
    bare = t.strip("<>")
    rendered = variant.format(
        t=t, t_lower=t.lower(), t_bare=bare, t_bare_lower=bare.lower(), t_spaces=f"<{bare.replace('_', ' ')}>"
    )
    out = e.unmask(f"Data anda: {rendered}, selesai.", r.session_id)
    nonce = t.rsplit("_", 1)[1].rstrip(">")
    assert NIK in out and nonce not in out  # restored, and no leftover of the placeholder


def test_restore_does_not_eat_surrounding_text():
    e, r, _ = _session()
    t = token(r.text, "<ID_NIK_1>")
    assert e.unmask(f"a {t} b", r.session_id) == f"a {NIK} b"
    assert e.unmask(f"x{t}y", r.session_id) == f"x{NIK}y"
    assert e.unmask(f"{t}.", r.session_id) == f"{NIK}."


# ---------------------------------------------------------------- streaming
def _stream(deanon, text, n):
    out = "".join(deanon.feed(text[i : i + n]) for i in range(0, len(text), n))
    return out + deanon.flush()


@pytest.mark.parametrize("size", [1, 2, 3, 5, 8, 13, 40, 200])
def test_stream_deanonymizer_handles_any_chunk_size(size):
    g = KawalLM()
    text, m = g.anonymize(f"NIK {NIK}, HP 081288889999, mail budi@contoh.co.id")
    reply = f"Halo. Data {text} sudah dicek. " + "Terima kasih. " * 12 + f"Sekali lagi {text}."
    expected = g.deanonymize(reply, m)
    assert NIK in expected and "<ID_" not in expected
    assert _stream(g.deanonymize_stream(m), reply, size) == expected


@pytest.mark.parametrize("size", [1, 2, 7])
def test_stream_deanonymizer_handles_rewritten_placeholders_split_across_chunks(size):
    e, r, m = _session()
    bare = token(r.text, "<ID_NIK_1>").strip("<>")
    reply = f"Nomor &lt;{bare.lower()}&gt; dan [{bare}] serta **<{bare}>** selesai"
    out = _stream(StreamDeanonymizer(m), reply, size)
    assert out == f"Nomor {NIK} dan {NIK} serta **{NIK}** selesai"


def test_stream_deanonymizer_passthrough_and_empty_map():
    assert _stream(StreamDeanonymizer({}), "tanpa placeholder", 3) == "tanpa placeholder"
    _, _, m = _session()
    plain = "kalimat biasa tanpa placeholder sama sekali. " * 5
    assert _stream(StreamDeanonymizer(m), plain, 4) == plain


def test_engine_unmask_stream_uses_the_vault_session():
    e, r, _ = _session()
    d = e.unmask_stream(r.session_id)
    pieces = [r.text[i : i + 3] for i in range(0, len(r.text), 3)]
    assert "".join(d.feed(p) for p in pieces) + d.flush() == f"NIK {NIK}"
