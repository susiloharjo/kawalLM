"""FastAPI / Starlette middleware.

    from fastapi import FastAPI
    from kawallm.integrations.fastapi import KawalLMMiddleware

    app = FastAPI()
    app.add_middleware(KawalLMMiddleware, paths=("/chat",), fields=("prompt", "message"))

For JSON requests on the given paths, string fields named in ``fields`` (and
OpenAI-style ``messages[].content``) are safety-checked and PII-masked before
your handler sees them. Violations return 400 with a JSON error.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from kawallm.audit import AuditLog, AuditSink, as_audit_log
from kawallm.core import KawalLMEngine


class KawalLMMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        engine: KawalLMEngine | None = None,
        paths: Iterable[str] = ("/",),
        fields: Iterable[str] = ("prompt", "message", "input", "query", "text"),
        max_body_bytes: int = 2_000_000,
        audit: AuditLog | AuditSink | None = None,
    ) -> None:
        self.app = app
        self.engine = engine or KawalLMEngine()
        self.paths = tuple(paths)
        self.fields = frozenset(fields)
        self.max_body_bytes = max_body_bytes
        self.audit = as_audit_log(audit) or self.engine.audit

    def _walk(self, obj: Any, counts: Counter, state: list[bool]) -> Any:
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                if isinstance(v, str) and (k in self.fields or k == "content"):
                    if self.engine.block_violations:
                        safety = self.engine.scan_safety(v)
                        if not safety.safe:
                            raise _Violation(safety.reason, list(safety.violations))
                    masked = self.engine.mask(v)
                    if masked.entities:
                        counts.update(m.entity for m in masked.entities)
                    if masked.text != v:
                        state[0] = True
                    out[k] = masked.text
                else:
                    out[k] = self._walk(v, counts, state)
            return out
        if isinstance(obj, list):
            return [self._walk(v, counts, state) for v in obj]
        return obj

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or scope.get("method") not in {"POST", "PUT", "PATCH"}
            or not scope["path"].startswith(self.paths)
        ):
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        if b"application/json" not in headers.get(b"content-type", b""):
            await self.app(scope, receive, send)
            return

        body = b""
        more = True
        while more:
            msg = await receive()
            body += msg.get("body", b"")
            more = msg.get("more_body", False)
            if len(body) > self.max_body_bytes:
                await _send_json(send, 413, {"error": "payload too large"})
                return
        counts: Counter = Counter()
        state = [False]
        ctx = {"method": scope.get("method", ""), "path": scope["path"]}
        try:
            payload = json.loads(body or b"null")
            sanitized = self._walk(payload, counts, state)
            new_body = json.dumps(sanitized, ensure_ascii=False).encode() if state[0] else body
        except _Violation as v:
            if self.audit:
                self.audit.record(
                    "fastapi",
                    entities=counts.elements(),
                    categories=v.categories,
                    blocked=True,
                    context=ctx,
                )
            await _send_json(send, 400, {"error": f"[KawalLM Violation] Request ditolak: {v.reason}"})
            return
        except json.JSONDecodeError:
            new_body = body

        if self.audit:
            self.audit.record("fastapi", entities=counts.elements(), blocked=False, context=ctx)

        if new_body is not body:
            scope = dict(scope)
            scope["headers"] = [
                (k, str(len(new_body)).encode() if k == b"content-length" else v) for k, v in scope["headers"]
            ]
        sent = False

        async def replay() -> Message:
            nonlocal sent
            if sent:
                return await receive()
            sent = True
            return {"type": "http.request", "body": new_body, "more_body": False}

        await self.app(scope, replay, send)


class _Violation(Exception):
    def __init__(self, reason: str, categories: list[str] = ()) -> None:
        super().__init__(reason)
        self.reason = reason
        self.categories = list(categories)


async def _send_json(send: Send, status: int, obj: dict) -> None:
    body = json.dumps(obj, ensure_ascii=False).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
        }
    )
    await send({"type": "http.response.body", "body": body})
