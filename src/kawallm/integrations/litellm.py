"""LiteLLM Proxy guardrail.

config.yaml::

    guardrails:
      - guardrail_name: kawallm
        litellm_params:
          guardrail: kawallm.integrations.litellm.KawalLMGuardrail
          mode: [pre_call, post_call]
          default_on: true
          mask_pii: true
          block_violations: true
          masking_mode: reversible     # token | redact | partial | reversible
          restore_output: true         # de-mask <ID_X_n> tokens in the response

Behaviour
  pre_call  : safety scan on user messages (block -> HTTP 400), PII masking on
              every message (all roles, str or multimodal text parts, and the JSON
              arguments of assistant ``tool_calls`` / ``function_call``).
  post_call : mask PII the model produced (output leakage), then, in reversible
              mode with ``restore_output``, put the caller's own values back.
  streaming : same, using a small hold-back buffer so a value split across
              chunks is still caught.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import re
import time
import uuid
from collections import Counter
from dataclasses import replace
from decimal import Decimal
from typing import Any

from fastapi import HTTPException
from litellm.integrations.custom_guardrail import CustomGuardrail

from kawallm.audit import AuditLog, JsonlFileSink, logging_sink
from kawallm.core import KawalLMEngine
from kawallm.pii.base import resolve_overlaps
from kawallm.placeholders import _LOOSE_RE, restore_tokens

_log = logging.getLogger("kawallm")
_SESSION_KEY = "kawallm_session"
_HOLDBACK = 64  # >= kawallm.placeholders.MAX_PLACEHOLDER_LEN
_MAX_TOOL_ARGUMENT_CHARS = 256_000  # larger tool-call arguments are refused (400), not parsed
_MAX_JSON_DEPTH = 64  # deeper JSON in tool-call arguments is refused (400)
_EMAIL_HOLD_CAP = 512  # longest whitespace-free run kept back while it may still be an e-mail (RFC 5321 limit is 254)


def _as_bool(v: Any) -> bool:
    if isinstance(v, str):
        return v.strip().lower() in {"1", "true", "yes", "on"}
    return bool(v)


def _as_mapping(v: Any) -> dict[str, str] | None:
    """``{"ID_PHONE": "reversible"}`` from YAML, or the string form ``"ID_PHONE=reversible,EMAIL=reversible"``."""
    if not v:
        return None
    if isinstance(v, str):
        pairs = [part.split("=", 1) for part in v.split(",") if part.strip()]
        if any(len(pair) != 2 for pair in pairs):
            raise ValueError(f"mode_by_entity must look like 'ID_PHONE=reversible,EMAIL=reversible', got {v!r}")
        return {k.strip(): val.strip() for k, val in pairs}
    return dict(v)


def _as_list(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [s.strip() for s in v.split(",") if s.strip()]
    return list(v)


class KawalLMGuardrail(CustomGuardrail):
    def __init__(
        self,
        mask_pii: bool = True,
        block_violations: bool = True,
        masking_mode: str = "token",
        restore_output: bool = True,
        mask_output: bool = True,
        scan_roles: list[str] | str | None = None,
        block_categories: list[str] | str | None = None,
        entities: list[str] | str | None = None,
        threshold: float = 1.0,
        block_status_code: int = 400,
        validate_wilayah: bool = True,
        block_safety_violations: bool | None = None,
        audit_log: bool | str = False,
        audit_file: str | None = None,
        audit_include_clean: bool = True,
        audit_include_user: bool = False,
        mode_by_entity: dict[str, str] | str | None = None,
        **kwargs: Any,
    ) -> None:
        if block_safety_violations is not None:  # alias used in older docs
            block_violations = block_safety_violations
        self.engine = KawalLMEngine(
            mask_pii=_as_bool(mask_pii),
            block_violations=_as_bool(block_violations),
            validate_wilayah=_as_bool(validate_wilayah),
            mode=masking_mode,
            mode_by_entity=_as_mapping(mode_by_entity),
            entities=_as_list(entities) or None,
            block_categories=_as_list(block_categories) or ("JUDOL_PINJOL", "SARA_HATE_SPEECH", "JAILBREAK"),
            threshold=float(threshold),
        )
        self.restore_output = _as_bool(restore_output)
        self.mask_output = _as_bool(mask_output)
        self.scan_roles = frozenset(_as_list(scan_roles) or ["user"])
        self.block_status_code = int(block_status_code)
        sinks = []
        if _as_bool(audit_log):
            sinks.append(logging_sink())
        if audit_file:
            sinks.append(JsonlFileSink(audit_file))
        self.audit = AuditLog(*sinks, include_clean=_as_bool(audit_include_clean)) if sinks else None
        self.audit_include_user = _as_bool(audit_include_user)
        super().__init__(**kwargs)

    # ------------------------------------------------------------ helpers
    @staticmethod
    def _caller_namespace(user_api_key_dict: Any) -> str:
        """Hash of the caller's identity. Vault keys are prefixed with it, so two callers never share a mapping."""
        ident = "|".join(str(getattr(user_api_key_dict, f, None) or "") for f in ("api_key", "team_id", "user_id"))
        return hashlib.sha256(ident.encode("utf-8")).hexdigest()[:16]

    def _session(self, data: dict, create: bool, user_api_key_dict: Any = None) -> str | None:
        """Vault key for this request, bound to the caller.

        On the request side the session id is generated by LiteLLM (``litellm_call_id``); a session id the client
        put in ``metadata`` is ignored, so a client cannot choose another request's mapping. The response side reads
        the id stored by the request side. Either way the key is prefixed with the caller's identity.
        """
        if create:
            sid = str(data.get("litellm_call_id") or uuid.uuid4().hex)
            if not isinstance(data.get("metadata"), dict):
                data["metadata"] = {}
            data["metadata"][_SESSION_KEY] = sid
        else:
            meta = data.get("metadata")
            if not isinstance(meta, dict):
                meta = data.get("litellm_metadata")
            sid = meta.get(_SESSION_KEY) if isinstance(meta, dict) else None
            if not sid:
                return None
        return f"{self._caller_namespace(user_api_key_dict)}:{sid}"

    def _check(self, text: str) -> None:
        if not self.engine.block_violations:
            return
        res = self.engine.scan_safety(text)
        if not res.safe:
            raise HTTPException(
                status_code=self.block_status_code,
                detail={
                    "error": f"[KawalLM Security Violation] Request diblokir: {res.message}",
                    "guardrail": "kawallm",
                    "categories": list(res.violations),
                },
            )

    def _mask_text(
        self,
        text: str,
        sid: str | None,
        counts: Counter | None,
        mode: str | None = None,
        context: str = "",
        after: str = "",
    ) -> str:
        """Mask ``text`` and add the entity types found to ``counts`` (used only for the audit trail).

        ``context`` precedes ``text`` (a JSON field name, the previous stream chunk): detectors that depend on a
        nearby keyword see it, but it is not part of the result.
        """
        res = self.engine.mask(text, sid, mode, context, after)
        if counts is not None:
            counts.update(m.entity for m in res.entities)
        return res.text

    def _report_guardrail(
        self,
        data: dict,
        counts: Counter,
        *,
        blocked: bool = False,
        categories: Any = (),
        started: float | None = None,
    ) -> None:
        """Write this guardrail's result into the request, where LiteLLM's dashboards and loggers read it.

        Only entity counts and category names are passed. No text and no matched values. Older LiteLLM versions
        without the helper are skipped, and a failure here never fails the request.
        """
        report = getattr(self, "add_standard_logging_guardrail_information_to_request_data", None)
        if report is None:
            return
        now = time.time()
        try:
            report(
                guardrail_json_response={"masked": dict(counts), "violations": sorted(set(categories))},
                request_data=data,
                guardrail_status="guardrail_intervened" if blocked else "success",
                guardrail_provider="kawallm",
                start_time=started,
                end_time=now,
                duration=(now - started) if started is not None else None,
                masked_entity_count=dict(counts),
            )
        except Exception:
            _log.warning("kawallm: could not write guardrail information for this request")

    def _record(
        self,
        source: str,
        data: dict,
        user_api_key_dict: Any,
        counts: Counter,
        blocked: bool = False,
        categories: Any = (),
    ) -> None:
        """Write one audit event (counts and categories only, never text or matched values)."""
        if self.audit is None:
            return
        context = {}
        for field in ("team_id", "key_alias", *(("user_id",) if self.audit_include_user else ())):
            value = getattr(user_api_key_dict, field, None)
            if value:
                context[field] = value
        model = data.get("model")
        if model:
            context["model"] = model
        self.audit.record(
            source,
            entities=counts.elements(),
            categories=categories,
            blocked=blocked,
            request_id=str(data.get("litellm_call_id") or "") or None,
            context=context,
        )

    def _mask_json_value(
        self,
        value: Any,
        sid: str | None,
        scan: bool,
        counts: Counter | None = None,
        mode: str | None = None,
        hint: str = "",
        depth: int = 0,
    ) -> Any:
        """Mask (and optionally safety-scan) every string/int leaf of a parsed JSON value.

        ``hint`` is the nearest field name: ``{"rekening": "1234567890"}`` is masked as "rekening 1234567890",
        so keyword-gated detectors (bank account, NPWP, passport, ...) work on JSON values too.
        """
        if isinstance(value, bool):
            return value
        if isinstance(value, str | int):
            text = str(value)
            if scan and isinstance(value, str):
                self._check(text)
            masked = self._mask_text(text, sid, counts, mode, hint)
            return value if masked == text else masked
        if isinstance(value, Decimal):  # a JSON float, parsed without losing digits: 3171011501900001.0
            text = format(value.to_integral_value() if value == value.to_integral_value() else value, "f")
            masked = self._mask_text(text, sid, counts, mode, hint)
            return value if masked == text else masked
        if isinstance(value, list | dict) and depth >= _MAX_JSON_DEPTH:
            raise HTTPException(status_code=400, detail="[KawalLM] Argumen tool_call terlalu dalam (JSON).")
        if isinstance(value, list):
            return [self._mask_json_value(v, sid, scan, counts, mode, hint, depth + 1) for v in value]
        if isinstance(value, dict):
            out: dict = {}
            for k, v in value.items():
                # A key can carry PII too ({"3171011501900001": ...}); it is masked like any value.
                key = self._mask_text(k, sid, counts, mode) if isinstance(k, str) else k
                while key in out:  # two keys can mask to the same token: keep both values
                    key = f"{key}#"
                out[key] = self._mask_json_value(
                    v, sid, scan, counts, mode, f"{k} " if isinstance(k, str) else hint, depth + 1
                )
            return out
        return value

    def _mask_arguments(
        self, args: str, sid: str | None, scan: bool, counts: Counter | None = None, mode: str | None = None
    ) -> str:
        """Tool-call arguments are a JSON string; mask leaves so the result stays valid JSON.

        A bare number such as ``{"nik": 3171011501900001}`` becomes the string ``"<ID_NIK>"``.
        Arguments that are not valid JSON fall back to plain text masking.
        """
        if len(args) > _MAX_TOOL_ARGUMENT_CHARS:
            raise HTTPException(status_code=400, detail="[KawalLM] Argumen tool_call terlalu besar.")
        try:
            parsed = json.loads(args, parse_float=Decimal)
        except RecursionError:
            raise HTTPException(status_code=400, detail="[KawalLM] Argumen tool_call terlalu dalam (JSON).") from None
        except ValueError:
            if scan:
                self._check(args)
            return self._mask_text(args, sid, counts, mode)
        masked = self._mask_json_value(parsed, sid, scan, counts, mode)
        return args if masked == parsed else json.dumps(masked, ensure_ascii=False, default=_json_default)

    @property
    def _output_mode(self) -> str:
        """Masking mode for new PII in a response: plain tokens, never the caller's reversible placeholders."""
        return "redact" if self.engine.mode == "redact" else "token"

    def _restores(self, sid: str | None) -> bool:
        return bool(sid) and self.restore_output and self.engine.reversible_enabled

    def _process_output(
        self, text: str, sid: str | None, counts: Counter | None = None, context: str = "", after: str = ""
    ) -> str:
        if self.mask_output:
            # Output-leakage protection. New PII produced by the model is not the caller's to restore.
            text = self._mask_text(text, None, counts, self._output_mode, context, after)
        if self._restores(sid):
            text = self.engine.unmask(text, sid)
        return text

    def _process_tool_args(self, args: str, sid: str | None, counts: Counter | None = None) -> str:
        """Same policy as :meth:`_process_output` for a tool call's JSON arguments (valid JSON is preserved)."""
        if self.mask_output:
            args = self._mask_arguments(args, None, False, counts, self._output_mode)
        if self._restores(sid):
            # Escape the value for a JSON string, so a restored value with a newline stays valid JSON.
            escaped = {k: json.dumps(v)[1:-1] for k, v in self.engine.vault.mapping(sid).items()}
            args = restore_tokens(args, escaped)
        return args

    @property
    def _tool_args_need_processing(self) -> bool:
        return self.mask_output or (self.restore_output and self.engine.reversible_enabled)

    # ------------------------------------------------------------ pre-call
    async def async_pre_call_hook(
        self,
        user_api_key_dict: Any,
        cache: Any,
        data: dict,
        call_type: str,
    ) -> dict | None:
        messages = data.get("messages")
        if not messages:
            return data
        sid = self._session(data, self.engine.reversible_enabled, user_api_key_dict)
        counts: Counter = Counter()
        started = time.time()
        try:
            self._process_messages(messages, sid, counts)
        except HTTPException as exc:
            detail = exc.detail if isinstance(exc.detail, dict) else {}
            self._report_guardrail(data, counts, blocked=True, categories=detail.get("categories", ()), started=started)
            self._record(
                "litellm.pre_call",
                data,
                user_api_key_dict,
                counts,
                blocked=True,
                categories=detail.get("categories", ()),
            )
            raise
        self._report_guardrail(data, counts, started=started)
        self._record("litellm.pre_call", data, user_api_key_dict, counts)
        return data

    def _process_messages(self, messages: list, sid: str | None, counts: Counter) -> None:
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            role = msg.get("role", "user")
            scan = role in self.scan_roles
            for call in msg.get("tool_calls") or []:
                fn = call.get("function") if isinstance(call, dict) else None
                if isinstance(fn, dict) and isinstance(fn.get("arguments"), str):
                    fn["arguments"] = self._mask_arguments(fn["arguments"], sid, scan, counts)
            legacy = msg.get("function_call")  # deprecated OpenAI field, still sent by some clients
            if isinstance(legacy, dict) and isinstance(legacy.get("arguments"), str):
                legacy["arguments"] = self._mask_arguments(legacy["arguments"], sid, scan, counts)
            content = msg.get("content")
            if isinstance(content, str):
                if scan:
                    self._check(content)
                msg["content"] = self._mask_text(content, sid, counts)
            elif isinstance(content, list):
                parts = [
                    p
                    for p in content
                    if isinstance(p, dict) and p.get("type") == "text" and isinstance(p.get("text"), str)
                ]
                if scan:
                    texts = [p["text"] for p in parts]
                    if len(texts) > 1:  # a phrase split over several parts must still be seen as one
                        self._check("".join(texts))
                        self._check(" ".join(texts))
                    for t in texts:
                        self._check(t)
                if len(parts) > 1:
                    self._mask_text_parts(parts, sid, counts)
                else:
                    for part in parts:
                        part["text"] = self._mask_text(part["text"], sid, counts)

    def _mask_text_parts(self, parts: list[dict], sid: str | None, counts: Counter) -> None:
        """Mask several text parts of one message as a single text, then give each part back its share.

        Masking part by part misses a value split across parts (e.g. "NIK 31710115" + "01900001"). The parts are
        joined for detection; a match is replaced by one token in the part where it starts, and the characters of
        that match that fall into later parts are removed there.
        """
        if not self.engine.mask_pii_enabled:
            return
        texts = [p["text"] for p in parts]
        joined = "".join(texts)
        # Joined detection finds values split across parts; per-part detection finds values that the concatenation
        # glues into a longer digit run (e.g. two complete NIKs back to back).
        candidates = list(self.engine.detect(joined))
        offset = 0
        for text in texts:
            candidates += [replace(m, start=m.start + offset, end=m.end + offset) for m in self.engine.detect(text)]
            offset += len(text)
        matches = resolve_overlaps(candidates)
        if not matches:
            return
        pairs = [(m, self.engine._replacement(m, sid, self.engine.mode_for(m.entity))) for m in matches]
        counts.update(m.entity for m in matches)
        start = 0
        for part, text in zip(parts, texts, strict=True):
            end = start + len(text)
            seg, cur = [], start
            for m, tok in pairs:
                if m.end <= start or m.start >= end:
                    continue
                s, e = max(m.start, start), min(m.end, end)
                seg.append(joined[cur:s])
                if m.start >= start:  # the token belongs to the part where the match begins
                    seg.append(tok)
                cur = e
            seg.append(joined[cur:end])
            part["text"] = "".join(seg)
            start = end

    # ------------------------------------------------------------ post-call
    async def async_post_call_success_hook(
        self,
        data: dict,
        user_api_key_dict: Any,
        response: Any,
    ) -> Any:
        sid = self._session(data, False, user_api_key_dict)
        counts: Counter = Counter()
        for choice in getattr(response, "choices", None) or []:
            message = getattr(choice, "message", None)
            if message is None:
                continue
            for field in _TEXT_FIELDS:
                value = getattr(message, field, None)
                if isinstance(value, str):
                    setattr(message, field, self._process_output(value, sid, counts))
            for block in getattr(message, "thinking_blocks", None) or []:
                text = block.get("thinking") if isinstance(block, dict) else getattr(block, "thinking", None)
                if isinstance(text, str):
                    cleaned = self._process_output(text, sid, counts)
                    if isinstance(block, dict):
                        block["thinking"] = cleaned
                    else:
                        block.thinking = cleaned
            calls = [getattr(tc, "function", None) for tc in getattr(message, "tool_calls", None) or []]
            calls.append(getattr(message, "function_call", None))  # deprecated single-call field
            for fn in calls:
                if fn is not None and isinstance(getattr(fn, "arguments", None), str):
                    fn.arguments = self._process_tool_args(fn.arguments, sid, counts)
        self._report_guardrail(data, counts)
        self._record("litellm.post_call", data, user_api_key_dict, counts)
        return response

    async def async_post_call_streaming_iterator_hook(
        self,
        user_api_key_dict: Any,
        response: Any,
        request_data: dict,
    ):
        sid = self._session(request_data, False, user_api_key_dict)
        counts: Counter = Counter()
        states: dict[int, _ChoiceStream] = {}  # one buffer per choice (n > 1)
        pending = None

        async for chunk in response:
            for choice in getattr(chunk, "choices", None) or []:
                st = states.setdefault(getattr(choice, "index", 0) or 0, _ChoiceStream(self, sid, counts))
                st.template = choice
                delta = getattr(choice, "delta", None)
                if delta is None:
                    continue
                for field in _TEXT_FIELDS:
                    value = getattr(delta, field, None)
                    if isinstance(value, str):
                        setattr(delta, field, st.feed_text(field, value))
                if getattr(delta, "tool_calls", None) and self._tool_args_need_processing:
                    st.hold_tool_calls(delta.tool_calls)
                fc = getattr(delta, "function_call", None)  # deprecated single-call field, streamed the same way
                if (
                    fc is not None
                    and isinstance(getattr(fc, "arguments", None), str)
                    and self._tool_args_need_processing
                ):
                    st.hold_function_call(fc)
                if getattr(choice, "finish_reason", None) is not None:
                    # Release what is still held into this chunk, before its finish_reason reaches the client.
                    _apply_tails(delta, *st.finish())
                    states.pop(getattr(choice, "index", 0) or 0, None)
            if pending is not None:
                yield pending
            pending = chunk

        if pending is not None:
            for extra in _attach_tails(pending, states):
                yield extra  # synthetic chunk(s), sent before the final (e.g. usage-only) chunk
            yield pending
        self._report_guardrail(request_data, counts)
        self._record("litellm.post_call", request_data, user_api_key_dict, counts)


def _json_default(value: Any) -> Any:
    if isinstance(value, Decimal):  # a float that was left unchanged
        return float(value)
    raise TypeError(f"{type(value).__name__} is not JSON serializable")


# Text fields of a response message or stream delta that reach the user and so need the same protection as
# ``content``. Each gets its own hold-back buffer when streamed.
_TEXT_FIELDS = ("content", "reasoning_content", "refusal")


class _TextChannel:
    """Hold-back buffer of one text field of one choice.

    Text is released in pieces that never split a placeholder, an entity or a digit run, each masked with the
    already released text as context before it and the still held text after it (so ``rekening`` right before or
    right after a number applies on either side of a cut).
    """

    CONTEXT = 160  # characters of released text kept as detector context

    def __init__(self, guard: KawalLMGuardrail, sid: str | None, counts: Counter) -> None:
        self.guard, self.sid, self.counts = guard, sid, counts
        self.buffer = ""
        self.context = ""

    def feed(self, text: str) -> str:
        self.buffer += text
        return self._release(final=False)

    def finish(self) -> str:
        return self._release(final=True)

    def _keep_entities_whole(self, buf: str, cut: int) -> int:
        """Move the cut back to the start of any entity it would split (e.g. "B 1234 ABC" or "A 1234567").

        Entities are at most about 64 characters, and the cut always leaves that much buffered, so every entity that
        crosses the cut is fully visible here. Detection also sees the released context, so keyword-gated entities keep
        their keyword. A split that starts inside already-released context is held for a bounded time only.
        """
        off = len(self.context)
        combined = self.context + buf
        detected = self.guard.engine.detect(combined)
        if not detected:
            return cut
        while cut > 0:
            crossing = [m for m in detected if m.start < off + cut < m.end]
            if not crossing:
                break
            start = min(m.start for m in crossing) - off
            if start <= 0:
                return 0 if len(buf) <= _EMAIL_HOLD_CAP else cut
            cut = start
        return cut

    def _release(self, final: bool) -> str:
        buf = self.buffer
        if final:
            ready, self.buffer = buf, ""
        else:
            if len(buf) <= _HOLDBACK:
                return ""
            limit = len(buf) - _HOLDBACK
            cut = -1
            for i in range(limit, 0, -1):
                if buf[i].isspace() and not buf[i - 1].isdigit() and buf[i - 1] not in "+-.":
                    cut = i
                    break
            if cut <= 0 and len(buf) > _HOLDBACK * 4:
                # Long whitespace-free stream (URL, base64, minified JSON): cut at the limit unless that
                # would split a placeholder candidate or a digit run.
                cut = limit
                for m in _LOOSE_RE.finditer(buf):
                    if m.start() < cut < m.end():
                        cut = m.start()
                        break
                while cut > 0 and (buf[cut - 1].isdigit() or buf[cut - 1] in "+-."):
                    cut -= 1
                # Never split an e-mail-like token: the detector could not see it whole. Hold the text until
                # the token ends (bounded, so a pathological stream still makes progress).
                left = re.search(r"[\w.+@-]*\Z", buf[:cut]).start()
                right = cut + re.match(r"[\w.+@-]*", buf[cut:]).end()
                if "@" in buf[left:right]:
                    if len(buf) <= _EMAIL_HOLD_CAP:
                        return ""
                    cut = left if left > 0 else cut
            if cut > 0 and self.guard.engine.mask_pii_enabled:
                cut = self._keep_entities_whole(buf, cut)
            if cut <= 0:
                return ""
            ready, self.buffer = buf[:cut], buf[cut:]
        if not ready:
            return ""
        out = self.guard._process_output(ready, self.sid, self.counts, self.context, after=self.buffer)
        self.context = (self.context + ready)[-self.CONTEXT :]
        return out


class _ChoiceStream:
    """Streaming state of one response choice: a text channel per field and the buffered tool-call arguments.

    Tool-call arguments are JSON, so they are collected and emitted whole at the end of the stream.
    """

    def __init__(self, guard: KawalLMGuardrail, sid: str | None, counts: Counter) -> None:
        self.guard, self.sid, self.counts = guard, sid, counts
        self.channels: dict[str, _TextChannel] = {}
        self.calls: dict[int, list] = {}  # tool call index -> [arguments so far, last fragment]
        self.legacy_fc: Any = None  # copy of the first deprecated function_call fragment (carries the name)
        self.legacy_args = ""
        self.template: Any = None

    def feed_text(self, field: str, text: str) -> str:
        channel = self.channels.get(field)
        if channel is None:
            channel = self.channels[field] = _TextChannel(self.guard, self.sid, self.counts)
        return channel.feed(text)

    def hold_tool_calls(self, tool_calls: list) -> None:
        for tc in tool_calls:
            fn = getattr(tc, "function", None)
            if fn is None or not isinstance(getattr(fn, "arguments", None), str):
                continue
            entry = self.calls.setdefault(getattr(tc, "index", 0) or 0, ["", tc])
            entry[0] += fn.arguments
            entry[1] = tc
            fn.arguments = ""  # id/name stay on the fragment; the arguments come back whole at the end

    def hold_function_call(self, fc: Any) -> None:
        if self.legacy_fc is None:
            self.legacy_fc = copy.copy(fc)
        self.legacy_args += fc.arguments
        fc.arguments = ""

    def finish(self) -> tuple[dict[str, str], list, Any]:
        tails = {field: tail for field, ch in self.channels.items() if (tail := ch.finish())}
        extras = []
        for raw, last in self.calls.values():
            extra = copy.copy(last)
            # Clients concatenate string fields across fragments, so only index + arguments may repeat.
            for name in ("id", "type"):
                if hasattr(extra, name):
                    setattr(extra, name, None)
            extra.function = copy.copy(last.function)
            extra.function.name = None
            extra.function.arguments = self.guard._process_tool_args(raw, self.sid, self.counts)
            extras.append(extra)
        self.calls.clear()
        legacy = None
        if self.legacy_fc is not None:
            legacy = self.legacy_fc
            legacy.name = None  # the name was already sent with the first fragment
            legacy.arguments = self.guard._process_tool_args(self.legacy_args, self.sid, self.counts)
            self.legacy_fc, self.legacy_args = None, ""
        return tails, extras, legacy


def _apply_tails(delta: Any, tails: dict[str, str], extras: list, legacy: Any) -> None:
    """Add what a stream still held to a delta that has not been sent yet."""
    for field, tail in tails.items():
        setattr(delta, field, (getattr(delta, field, None) or "") + tail)
    if extras:
        delta.tool_calls = [*(getattr(delta, "tool_calls", None) or []), *extras]
    if legacy is not None:
        delta.function_call = legacy


def _attach_tails(pending: Any, states: dict[int, _ChoiceStream]) -> list:
    """Put what the streams still hold onto ``pending`` (or onto new chunks when it has no matching choice).

    The last chunk of a stream may be a usage-only chunk with ``choices == []``; the held-back text then goes
    into a synthetic chunk placed before it instead of being dropped.
    """
    synthetic = []
    for index, st in states.items():
        tails, extras, legacy = st.finish()
        if not tails and not extras and legacy is None:
            continue
        choice = next(
            (c for c in getattr(pending, "choices", None) or [] if (getattr(c, "index", 0) or 0) == index), None
        )
        if choice is not None and getattr(choice, "delta", None) is not None:
            _apply_tails(choice.delta, tails, extras, legacy)
        elif st.template is not None:
            chunk = copy.copy(pending)
            new_choice = copy.copy(st.template)
            new_choice.delta = copy.copy(st.template.delta)
            for field in _TEXT_FIELDS:
                if hasattr(new_choice.delta, field):
                    setattr(new_choice.delta, field, None)
            new_choice.delta.tool_calls = None
            new_choice.delta.function_call = None
            _apply_tails(new_choice.delta, tails, extras, legacy)
            new_choice.finish_reason = None
            chunk.choices = [new_choice]
            synthetic.append(chunk)
    return synthetic
