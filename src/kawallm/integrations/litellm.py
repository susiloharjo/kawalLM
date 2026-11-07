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
              every message (all roles, str or multimodal text parts).
  post_call : mask PII the model produced (output leakage), then, in reversible
              mode with ``restore_output``, put the caller's own values back.
  streaming : same, using a small hold-back buffer so a value split across
              chunks is still caught.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import HTTPException
from litellm.integrations.custom_guardrail import CustomGuardrail

from kawallm.core import KawalLMEngine

_SESSION_KEY = "kawallm_session"
_HOLDBACK = 48


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

    def _process_output(self, text: str, sid: str | None) -> str:
        if self.mask_output:
            # Output-leakage protection. Always plain tokens here: new PII produced by the
            # model is not the caller's to restore.
            text = self.engine.mask_pii(text, mode="redact" if self.engine.mode == "redact" else "token")
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
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            role = msg.get("role", "user")
            content = msg.get("content")
            if isinstance(content, str):
                if role in self.scan_roles:
                    self._check(content)
                msg["content"] = self.engine.mask_pii(content, sid)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
                        if role in self.scan_roles:
                            self._check(part["text"])
                        part["text"] = self.engine.mask_pii(part["text"], sid)
        return data

    # ------------------------------------------------------------ post-call
    async def async_post_call_success_hook(
        self,
        data: dict,
        user_api_key_dict: Any,
        response: Any,
    ) -> Any:
        sid = self._session(data, create=False)
        for choice in getattr(response, "choices", None) or []:
            message = getattr(choice, "message", None)
            if message is None:
                continue
            if isinstance(getattr(message, "content", None), str):
                message.content = self._process_output(message.content, sid)
            for tc in getattr(message, "tool_calls", None) or []:
                fn = getattr(tc, "function", None)
                if fn is not None and isinstance(getattr(fn, "arguments", None), str) and sid:
                    fn.arguments = self.engine.unmask(fn.arguments, sid)
        return response

    async def async_post_call_streaming_iterator_hook(
        self,
        user_api_key_dict: Any,
        response: Any,
        request_data: dict,
    ):
        sid = self._session(request_data, create=False)
        buffer = ""
        pending = None

        def take_ready(final: bool) -> str:
            nonlocal buffer
            if final:
                ready, buffer = buffer, ""
                return self._process_output(ready, sid) if ready else ""
            if len(buffer) <= _HOLDBACK:
                return ""
            limit = len(buffer) - _HOLDBACK
            cut = -1
            for i in range(limit, 0, -1):
                if buffer[i].isspace() and not buffer[i - 1].isdigit() and buffer[i - 1] not in "+-.":
                    cut = i
                    break
            if cut <= 0:
                return ""
            ready, buffer = buffer[:cut], buffer[cut:]
            return self._process_output(ready, sid)

        def delta_of(chunk: Any) -> Any:
            choices = getattr(chunk, "choices", None) or []
            return getattr(choices[0], "delta", None) if choices else None

        async for chunk in response:
            delta = delta_of(chunk)
            if delta is not None and isinstance(getattr(delta, "content", None), str):
                buffer += delta.content
                delta.content = take_ready(final=False)
            if pending is not None:
                yield pending
            pending = chunk

        tail = take_ready(final=True)
        if pending is not None:
            delta = delta_of(pending)
            if tail and delta is not None:
                delta.content = (getattr(delta, "content", None) or "") + tail
            yield pending
