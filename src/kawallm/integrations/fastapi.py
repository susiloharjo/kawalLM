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
from collections.abc import Iterable
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from kawallm.core import KawalLMEngine


class KawalLMMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        engine: KawalLMEngine | None = None,
        paths: Iterable[str] = ("/",),
        fields: Iterable[str] = ("prompt", "message", "input", "query", "text"),
        max_body_bytes: int = 2_000_000,
    ) -> None:
        self.app = app
        self.engine = engine or KawalLMEngine()
        self.paths = tuple(paths)
        self.fields = frozenset(fields)
        self.max_body_bytes = max_body_bytes

    def _walk(self, obj: Any) -> Any:
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                if isinstance(v, str) and (k in self.fields or k == "content"):
                    ok, reason = self.engine.check_safety(v)
                    if not ok:
                        raise _Violation(reason)
                    out[k] = self.engine.mask_pii(v)
                else:
                    out[k] = self._walk(v)
            return out
        if isinstance(obj, list):
            return [self._walk(v) for v in obj]
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
        try:
            payload = json.loads(body or b"null")
            new_body = json.dumps(self._walk(payload), ensure_ascii=False).encode()
        except _Violation as v:
            await _send_json(send, 400, {"error": f"[KawalLM Violation] Request ditolak: {v}"})
            return
        except json.JSONDecodeError:
            new_body = body

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
    pass


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
