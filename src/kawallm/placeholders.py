"""Reversible placeholders: ``<ID_NIK_1_a3f2c9>`` = entity, running number, per-session nonce.

The nonce is random and belongs to one session (it is part of every key of the session map). It makes a
placeholder impossible to forge: text a user types, or a placeholder from another session's map, never
restores anything. Because restoring is gated on the exact (entity, number, nonce) in the map, it can safely
be tolerant about how the LLM rewrote the placeholder (case, brackets, ``&lt;``/``&gt;``, spaces).
"""

from __future__ import annotations

import re
import secrets

_NONCE_LEN = 6
_KEY_RE = re.compile(rf"^<((?:ID_[A-Z_]+?)|EMAIL|IP_ADDRESS)_(\d+)_([0-9a-f]{{{_NONCE_LEN}}})>$")
# How an LLM may hand a placeholder back: any of <>, &lt;&gt;, [], () around it (or none), any case,
# spaces/underscores/colons/dashes as separators. Matching is only a *candidate*: restore checks the map.
_OPEN = r"(?:(?:<|&lt;|&#60;|\[|\()\s*|(?<![A-Za-z0-9]))"  # an opening bracket, or the start of a bare word
_CLOSE = r"(?:\s*(?:>|&gt;|&#62;|\]|\)))?"
_LOOSE_RE = re.compile(
    rf"{_OPEN}(ID(?:[\s_]+[A-Za-z]+)+?|EMAIL|IP[\s_]+ADDRESS)[\s_]+(\d+)[\s_:\-]+([0-9a-f]{{{_NONCE_LEN}}})(?![0-9A-Za-z]){_CLOSE}",
    re.IGNORECASE,
)

# Longest realistic rewritten placeholder (&lt;ID_BPJS_KES_999_abcdef&gt; plus some spaces); used as stream hold-back.
MAX_PLACEHOLDER_LEN = 64


def new_nonce() -> str:
    return secrets.token_hex(_NONCE_LEN // 2)


def nonce_of(mapping: dict[str, str]) -> str | None:
    """The nonce shared by the keys of a session map, or ``None`` for an empty/legacy map."""
    for key in mapping:
        m = _KEY_RE.match(key)
        if m:
            return m.group(3)
    return None


def assign_token(fwd: dict[str, str], rev: dict[str, str], entity: str, original: str) -> str:
    """Return the token for ``original``, creating ``<ENTITY_n_nonce>`` if new. Mutates both maps."""
    token = rev.get(original)
    if token is None:
        nonce = nonce_of(fwd) or new_nonce()
        n = sum(1 for t in fwd if t.startswith(f"<{entity}_")) + 1
        token = f"<{entity}_{n}_{nonce}>"
        fwd[token] = original
        rev[original] = token
    return token


def _lookup(mapping: dict[str, str]) -> dict[str, str]:
    return {k.lower(): v for k, v in mapping.items()}


def _canonical(m: re.Match) -> str:
    entity = re.sub(r"[\s_]+", "_", m.group(1))
    return f"<{entity}_{m.group(2)}_{m.group(3)}>".lower()


def restore_tokens(text: str, mapping: dict[str, str]) -> str:
    """Put the original values back for every placeholder in ``text`` that belongs to ``mapping``.

    Tolerates placeholders the LLM rewrote (see module doc). Anything not in ``mapping`` is left untouched,
    including well-formed placeholders from another session. Keys that do not have the nonce format
    (maps made by 0.1.x) are replaced by exact match only.
    """
    if not mapping or not text:
        return text
    lookup = _lookup(mapping)
    text = _LOOSE_RE.sub(lambda m: lookup.get(_canonical(m), m.group()), text)
    for key, value in mapping.items():
        if not _KEY_RE.match(key) and key in text:
            text = text.replace(key, value)
    return text


class StreamDeanonymizer:
    """Restore placeholders in a streamed response, even when they are split across chunks.

        d = StreamDeanonymizer(session_map)
        for chunk in llm_stream:
            out = d.feed(chunk)   # may be "" while a placeholder is incomplete
            ...
        tail = d.flush()

    It holds back the last ``MAX_PLACEHOLDER_LEN`` characters (and never cuts through a complete placeholder),
    so output lags by roughly that many characters until :meth:`flush`.
    """

    def __init__(self, mapping: dict[str, str], holdback: int = MAX_PLACEHOLDER_LEN) -> None:
        self.mapping = dict(mapping)
        self.holdback = holdback
        self._buf = ""

    def feed(self, chunk: str) -> str:
        if not self.mapping:
            return chunk
        self._buf += chunk
        cut = max(0, len(self._buf) - self.holdback)
        for m in _LOOSE_RE.finditer(self._buf):
            if m.start() < cut < m.end():
                cut = m.start()
                break
        ready, self._buf = self._buf[:cut], self._buf[cut:]
        return restore_tokens(ready, self.mapping)

    def flush(self) -> str:
        ready, self._buf = self._buf, ""
        return restore_tokens(ready, self.mapping)
