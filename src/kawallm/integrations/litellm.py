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
import json
import uuid
from collections import Counter
from typing import Any

from fastapi import HTTPException
from litellm.integrations.custom_guardrail import CustomGuardrail

from kawallm.audit import AuditLog, JsonlFileSink, logging_sink
from kawallm.core import KawalLMEngine
from kawallm.placeholders import _LOOSE_RE, StreamDeanonymizer

_SESSION_KEY = "kawallm_session"
_HOLDBACK = 64  # >= kawallm.placeholders.MAX_PLACEHOLDER_LEN


def _as_bool(v: Any) -> bool:
    if isinstance(v, str):
        return v.strip().lower() in {"1", "true", "yes", "on"}
    return bool(v)


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
        **kwargs: Any,
    ) -> None:
        if block_safety_violations is not None:  # alias used in older docs
            block_violations = block_safety_violations
        self.engine = KawalLMEngine(
            mask_pii=_as_bool(mask_pii),
            block_violations=_as_bool(block_violations),
            validate_wilayah=_as_bool(validate_wilayah),
            mode=masking_mode,
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
    def _session(data: dict, create: bool) -> str | None:
        meta = data.get("metadata")
        if not isinstance(meta, dict):
            meta = data.get("litellm_metadata")
        if isinstance(meta, dict) and meta.get(_SESSION_KEY):
            return meta[_SESSION_KEY]
        if not create:
            return None
        sid = str(data.get("litellm_call_id") or uuid.uuid4().hex)
        if not isinstance(data.get("metadata"), dict):
            data["metadata"] = {}
        data["metadata"][_SESSION_KEY] = sid
        return sid

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

    def _mask_text(self, text: str, sid: str | None, counts: Counter | None, mode: str | None = None) -> str:
        """Mask ``text`` and add the entity types found to ``counts`` (used only for the audit trail)."""
        res = self.engine.mask(text, sid, mode)
        if counts is not None:
            counts.update(m.entity for m in res.entities)
        return res.text

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

    def _mask_json_value(self, value: Any, sid: str | None, scan: bool, counts: Counter | None = None) -> Any:
        """Mask (and optionally safety-scan) every string/int leaf of a parsed JSON value."""
        if isinstance(value, bool):
            return value
        if isinstance(value, str | int):
            text = str(value)
            if scan and isinstance(value, str):
                self._check(text)
            masked = self._mask_text(text, sid, counts)
            return value if masked == text else masked
        if isinstance(value, list):
            return [self._mask_json_value(v, sid, scan, counts) for v in value]
        if isinstance(value, dict):
            return {k: self._mask_json_value(v, sid, scan, counts) for k, v in value.items()}
        return value

    def _mask_arguments(self, args: str, sid: str | None, scan: bool, counts: Counter | None = None) -> str:
        """Tool-call arguments are a JSON string; mask leaves so the result stays valid JSON.

        A bare number such as ``{"nik": 3171011501900001}`` becomes the string ``"<ID_NIK>"``.
        Arguments that are not valid JSON fall back to plain text masking.
        """
        try:
            parsed = json.loads(args)
        except ValueError:
            if scan:
                self._check(args)
            return self._mask_text(args, sid, counts)
        masked = self._mask_json_value(parsed, sid, scan, counts)
        return args if masked == parsed else json.dumps(masked, ensure_ascii=False)

    def _process_output(self, text: str, sid: str | None, counts: Counter | None = None) -> str:
        if self.mask_output:
            # Output-leakage protection. Always plain tokens here: new PII produced by the
            # model is not the caller's to restore.
            text = self._mask_text(text, None, counts, "redact" if self.engine.mode == "redact" else "token")
        if sid and self.restore_output and self.engine.mode == "reversible":
            text = self.engine.unmask(text, sid)
        return text

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
        sid = self._session(data, create=self.engine.mode == "reversible")
        counts: Counter = Counter()
        try:
            self._process_messages(messages, sid, counts)
        except HTTPException as exc:
            detail = exc.detail if isinstance(exc.detail, dict) else {}
            self._record(
                "litellm.pre_call",
                data,
                user_api_key_dict,
                counts,
                blocked=True,
                categories=detail.get("categories", ()),
            )
            raise
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
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
                        if scan:
                            self._check(part["text"])
                        part["text"] = self._mask_text(part["text"], sid, counts)

    # ------------------------------------------------------------ post-call
    async def async_post_call_success_hook(
        self,
        data: dict,
        user_api_key_dict: Any,
        response: Any,
    ) -> Any:
        sid = self._session(data, create=False)
        counts: Counter = Counter()
        for choice in getattr(response, "choices", None) or []:
            message = getattr(choice, "message", None)
            if message is None:
                continue
            if isinstance(getattr(message, "content", None), str):
                message.content = self._process_output(message.content, sid, counts)
            for tc in getattr(message, "tool_calls", None) or []:
                fn = getattr(tc, "function", None)
                if fn is not None and isinstance(getattr(fn, "arguments", None), str) and sid:
                    fn.arguments = self.engine.unmask(fn.arguments, sid)
        self._record("litellm.post_call", data, user_api_key_dict, counts)
        return response

    async def async_post_call_streaming_iterator_hook(
        self,
        user_api_key_dict: Any,
        response: Any,
        request_data: dict,
    ):
        sid = self._session(request_data, create=False)
        counts: Counter = Counter()
        buffer = ""
        pending = None
        tc_streams: dict[int, tuple[StreamDeanonymizer, Any]] = {}

        def flush_tool_calls(target: Any) -> None:
            """Emit what the per-call de-anonymizers still hold as extra fragments on ``target``.

            ``target`` must be a delta that has not been yielded yet. Appending to the call's own last
            fragment is wrong: with parallel tool calls that chunk is long gone. Clients accumulate
            fragments by ``index``, so a trailing fragment for an earlier index is valid.
            """
            extras = []
            for deanon, last_tc in tc_streams.values():
                rem = deanon.flush()
                if rem:
                    extra = copy.copy(last_tc)
                    extra.function = copy.copy(last_tc.function)
                    extra.function.arguments = rem
                    extras.append(extra)
            tc_streams.clear()
            if extras and target is not None:
                target.tool_calls = [*(getattr(target, "tool_calls", None) or []), *extras]

        def take_ready(final: bool) -> str:
            nonlocal buffer
            if final:
                ready, buffer = buffer, ""
                return self._process_output(ready, sid, counts) if ready else ""
            if len(buffer) <= _HOLDBACK:
                return ""
            limit = len(buffer) - _HOLDBACK
            cut = -1
            for i in range(limit, 0, -1):
                if buffer[i].isspace() and not buffer[i - 1].isdigit() and buffer[i - 1] not in "+-.":
                    cut = i
                    break
            if cut <= 0 and len(buffer) > _HOLDBACK * 4:
                # Fallback for long whitespace-free streams (URLs, base64, minified JSON):
                # cut at limit unless that splits a placeholder candidate or digit run.
                cut = limit
                for m in _LOOSE_RE.finditer(buffer):
                    if m.start() < cut < m.end():
                        cut = m.start()
                        break
                while cut > 0 and (buffer[cut - 1].isdigit() or buffer[cut - 1] in "+-."):
                    cut -= 1
            if cut <= 0:
                return ""
            ready, buffer = buffer[:cut], buffer[cut:]
            return self._process_output(ready, sid, counts)

        def delta_of(chunk: Any) -> Any:
            choices = getattr(chunk, "choices", None) or []
            return getattr(choices[0], "delta", None) if choices else None

        async for chunk in response:
            delta = delta_of(chunk)
            if delta is not None:
                if isinstance(getattr(delta, "content", None), str):
                    buffer += delta.content
                    delta.content = take_ready(final=False)
                tcs = getattr(delta, "tool_calls", None)
                if tcs and sid and self.restore_output and self.engine.mode == "reversible":
                    for tc in tcs:
                        fn = getattr(tc, "function", None)
                        if fn is not None and isinstance(getattr(fn, "arguments", None), str):
                            idx = getattr(tc, "index", 0) or 0
                            deanon, _ = tc_streams.get(idx, (None, None))
                            if deanon is None:
                                deanon = self.engine.unmask_stream(sid)
                            fn.arguments = deanon.feed(fn.arguments)
                            tc_streams[idx] = (deanon, tc)
                elif tc_streams:
                    flush_tool_calls(delta)
            if pending is not None:
                yield pending
            pending = chunk

        tail = take_ready(final=True)
        if tc_streams:
            flush_tool_calls(delta_of(pending) if pending is not None else None)
        if pending is not None:
            delta = delta_of(pending)
            if tail and delta is not None:
                delta.content = (getattr(delta, "content", None) or "") + tail
            yield pending
        self._record("litellm.post_call", request_data, user_api_key_dict, counts)
