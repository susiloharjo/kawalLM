"""Audit trail: what KawalLM did to a request, without ever recording the data itself.

An :class:`AuditEvent` carries the action (``pass`` / ``masked`` / ``blocked``), the number of *occurrences*
of each PII entity type, and the violated safety categories. It never contains the matched values, the text, the
reversible-masking session id, or the vault. ``context`` holds identifiers supplied by the caller
(team, application, key alias): keep PII out of them.

    from kawallm import KawalLM
    from kawallm.audit import AuditLog, logging_sink, JsonlFileSink

    guard = KawalLM(audit=AuditLog(logging_sink(), JsonlFileSink("audit.jsonl")))
    guard.scan("NIK saya 3171011501900001", context={"app": "hr-bot"})
"""

from __future__ import annotations

import json
import logging
import threading
import uuid
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

_log = logging.getLogger("kawallm")
_MAX_CONTEXT_VALUE = 200


@dataclass(frozen=True)
class AuditEvent:
    ts: str
    source: str
    action: str  # "pass" | "masked" | "blocked"
    request_id: str
    entities: dict[str, int] = field(default_factory=dict)
    categories: list[str] = field(default_factory=list)
    context: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "ts": self.ts,
            "source": self.source,
            "action": self.action,
            "request_id": self.request_id,
            "entities": dict(self.entities),
            "categories": list(self.categories),
            "context": dict(self.context),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True)


AuditSink = Callable[[AuditEvent], None]


def logging_sink(name: str = "kawallm.audit", level: int = logging.INFO) -> AuditSink:
    """Sink that writes one JSON line per event to a standard ``logging`` logger."""
    logger = logging.getLogger(name)

    def sink(event: AuditEvent) -> None:
        logger.log(level, "%s", event.to_json())

    return sink


class JsonlFileSink:
    """Append one JSON object per line to ``path`` (thread-safe)."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def __call__(self, event: AuditEvent) -> None:
        line = event.to_json() + "\n"
        with self._lock, self.path.open("a", encoding="utf-8") as f:
            f.write(line)


def _clean_context(context: Mapping[str, object] | None) -> dict[str, str]:
    if not context:
        return {}
    return {str(k): str(v)[:_MAX_CONTEXT_VALUE] for k, v in context.items() if v is not None and v != ""}


class AuditLog:
    """Fan-out of audit events to one or more sinks.

    A failing sink never breaks the request: the error is logged on the ``kawallm`` logger and the
    remaining sinks still run. ``include_clean=False`` drops ``pass`` events to cut volume.
    """

    def __init__(self, *sinks: AuditSink, include_clean: bool = True) -> None:
        self.sinks = sinks or (logging_sink(),)
        self.include_clean = include_clean

    def record(
        self,
        source: str,
        *,
        entities: Iterable[str] = (),
        categories: Iterable[str] = (),
        blocked: bool = False,
        request_id: str | None = None,
        context: Mapping[str, object] | None = None,
    ) -> AuditEvent | None:
        counts = Counter(entities)
        cats = sorted(set(categories))
        action = "blocked" if blocked else ("masked" if counts else "pass")
        if action == "pass" and not self.include_clean:
            return None
        event = AuditEvent(
            ts=datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            source=source,
            action=action,
            request_id=request_id or uuid.uuid4().hex,
            entities=dict(sorted(counts.items())),
            categories=cats,
            context=_clean_context(context),
        )
        for sink in self.sinks:
            try:
                sink(event)
            except Exception:  # an audit failure must not take the request down
                _log.exception("kawallm audit sink %r failed", sink)
        return event


def as_audit_log(audit: AuditLog | AuditSink | None) -> AuditLog | None:
    """Accept an :class:`AuditLog`, a bare callable sink, or ``None``."""
    if audit is None or isinstance(audit, AuditLog):
        return audit
    return AuditLog(audit)
