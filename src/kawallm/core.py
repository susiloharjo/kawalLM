"""KawalLM engine: safety scanning + PII masking + reversible vault."""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from typing import Protocol, runtime_checkable

from .audit import AuditLog, AuditSink, as_audit_log
from .pii import ALL_ENTITIES, DETECTORS, PIIMatch, detect_pii, expand_entities
from .pii.base import PRIORITY
from .pii.quasi import GENERALIZERS
from .placeholders import StreamDeanonymizer, assign_token, restore_tokens
from .safety import SafetyResult, SafetyScanner

MASK_MODES = ("token", "redact", "partial", "reversible", "generalize")


def _validate_mode_by_entity(mapping: Mapping[str, str] | None) -> dict[str, str]:
    """``{"ID_PHONE": "reversible", ...}`` checked against the known entity names and mask modes."""
    if not mapping:
        return {}
    known = {*PRIORITY, *DETECTORS}
    out: dict[str, str] = {}
    for entity, mode in dict(mapping).items():
        if entity not in known:
            raise ValueError(f"unknown entity {entity!r} in mode_by_entity; expected one of {sorted(known)}")
        if mode not in MASK_MODES:
            raise ValueError(f"mode_by_entity[{entity!r}] must be one of {MASK_MODES}, got {mode!r}")
        out[entity] = mode
    return out


@dataclass
class MaskResult:
    text: str
    entities: list[PIIMatch] = field(default_factory=list)
    session_id: str | None = None

    @property
    def found(self) -> bool:
        return bool(self.entities)


@runtime_checkable
class VaultBackend(Protocol):
    """Pluggable session store interface for reversible masking (e.g. Redis-backed)."""

    def token_for(self, session_id: str, entity: str, original: str) -> str: ...
    def mapping(self, session_id: str) -> dict[str, str]: ...
    def drop(self, session_id: str) -> None: ...


class Vault:
    """Thread-safe, in-memory, TTL-bounded token ↔ original mapping per session.

    Nothing is persisted; entries expire after ``ttl`` seconds. For multi-replica
    deployments use sticky sessions or plug in your own :class:`VaultBackend`.
    """

    def __init__(self, ttl: float = 600.0, max_sessions: int = 100_000) -> None:
        self.ttl = ttl
        self.max_sessions = max_sessions
        self._data: dict[str, tuple[float, dict[str, str], dict[str, str]]] = {}
        self._lock = threading.Lock()

    def _purge(self, now: float) -> None:
        # Dict preserves insertion order and re-inserts move to the end, so the oldest
        # expiry timestamps are always at the front (O(expired) eviction).
        while self._data:
            k, (exp, _, _) = next(iter(self._data.items()))
            if exp >= now and len(self._data) <= self.max_sessions:
                break
            del self._data[k]

    def token_for(self, session_id: str, entity: str, original: str) -> str:
        now = time.monotonic()
        with self._lock:
            exp, fwd, rev = self._data.pop(session_id, (0.0, {}, {}))
            if exp < now:  # unknown or expired: start clean, never revive old mappings by extending the TTL
                fwd, rev = {}, {}
            token = assign_token(fwd, rev, entity, original)
            self._data[session_id] = (now + self.ttl, fwd, rev)
            self._purge(now)
            return token

    def mapping(self, session_id: str) -> dict[str, str]:
        with self._lock:
            item = self._data.get(session_id)
            if not item or item[0] < time.monotonic():
                return {}
            return dict(item[1])

    def drop(self, session_id: str) -> None:
        with self._lock:
            self._data.pop(session_id, None)


class KawalLMEngine:
    def __init__(
        self,
        mask_pii: bool = True,
        block_violations: bool = True,
        mode: str = "token",
        entities: Iterable[str] | None = None,
        block_categories: Iterable[str] = ("JUDOL_PINJOL", "SARA_HATE_SPEECH", "JAILBREAK"),
        threshold: float = 1.0,
        extra_dictionaries: Iterable[str] = (),
        vault_ttl: float = 600.0,
        redact_text: str = "[REDACTED]",
        validate_wilayah: bool = True,
        audit: AuditLog | AuditSink | None = None,
        vault: VaultBackend | None = None,
        mode_by_entity: Mapping[str, str] | None = None,
    ) -> None:
        if mode not in MASK_MODES:
            raise ValueError(f"mode must be one of {MASK_MODES}")
        self.mask_pii_enabled = mask_pii
        self.block_violations = block_violations
        self.mode = mode
        self.mode_by_entity = _validate_mode_by_entity(mode_by_entity)
        self.entities = expand_entities(entities) if entities else ALL_ENTITIES
        self.redact_text = redact_text
        self.validate_wilayah = validate_wilayah
        self.scanner = SafetyScanner(
            extra_dictionaries=extra_dictionaries,
            threshold=threshold,
            block_categories=block_categories,
        )
        self.vault: VaultBackend = vault if vault is not None else Vault(ttl=vault_ttl)
        self.audit = as_audit_log(audit)

    # ---------------- safety ----------------
    def scan_safety(self, text: str) -> SafetyResult:
        return self.scanner.scan(text)

    def check_safety(self, text: str) -> tuple[bool, str]:
        """PRD interface: returns (is_safe, reason). Always safe if blocking disabled."""
        res = self.scanner.scan(text)
        if not self.block_violations:
            return True, ""
        return res.safe, res.reason

    # ---------------- PII ----------------
    def detect(self, text: str) -> list[PIIMatch]:
        return detect_pii(text, self.entities, check_region=self.validate_wilayah)

    @property
    def reversible_enabled(self) -> bool:
        """True when any entity is masked reversibly (the engine mode, or an entry of ``mode_by_entity``)."""
        return self.mode == "reversible" or "reversible" in self.mode_by_entity.values()

    def mode_for(self, entity: str, mode: str | None = None) -> str:
        """Mask mode of one entity: an explicit ``mode`` wins, then ``mode_by_entity``, then the engine mode."""
        return mode or self.mode_by_entity.get(entity) or self.mode

    def _replacement(self, m: PIIMatch, session_id: str | None, mode: str) -> str:
        if mode == "reversible":
            assert session_id is not None
            return self.vault.token_for(session_id, m.entity, m.text)
        if mode == "generalize":
            # Lower the precision instead of replacing: a birth date becomes its year, an address its area, and so on.
            # Entities without a generalisation (an ID number, say) fall back to the plain token.
            generalize = GENERALIZERS.get(m.entity)
            generalized = generalize(m) if generalize else None
            return generalized if generalized is not None else f"<{m.entity}>"
        if mode == "redact":
            return self.redact_text
        if mode == "partial":
            keep = 4
            out, seen = [], 0
            for ch in reversed(m.text):
                if ch.isalnum():
                    seen += 1
                    out.append(ch if seen <= keep else "*")
                else:
                    out.append(ch)
            return "".join(reversed(out))
        return f"<{m.entity}>"

    def mask(self, text: str, session_id: str | None = None, mode: str | None = None, context: str = "") -> MaskResult:
        """Mask PII. ``mode`` overrides the engine mode for this call only.

        ``context`` is text that precedes ``text`` and was already handled (for example the previous chunk of a
        stream, or a JSON field name). Detectors see it, so a keyword such as ``rekening`` still applies to a
        number in ``text``; it is neither returned nor masked, and values that straddle the boundary are left
        to the caller that owns the earlier text.
        """
        explicit = mode  # an explicit mode applies to every entity and replaces mode_by_entity for this call
        if not self.mask_pii_enabled or not text:
            return MaskResult(text, [], session_id)
        needs_session = explicit == "reversible" or (explicit is None and self.reversible_enabled)
        if needs_session and session_id is None:
            session_id = uuid.uuid4().hex
        offset = len(context)
        matches = self.detect(context + text) if context else self.detect(text)
        if offset:
            matches = [replace(m, start=m.start - offset, end=m.end - offset) for m in matches if m.start >= offset]
        if not matches:
            return MaskResult(text, [], session_id)
        parts, last = [], 0
        for m in matches:
            parts.append(text[last : m.start])
            parts.append(self._replacement(m, session_id, self.mode_for(m.entity, explicit)))
            last = m.end
        parts.append(text[last:])
        return MaskResult("".join(parts), matches, session_id)

    def mask_pii(self, text: str, session_id: str | None = None, mode: str | None = None) -> str:
        """PRD interface: return the masked text."""
        return self.mask(text, session_id, mode).text

    def unmask(self, text: str, session_id: str) -> str:
        """Restore ``<ID_X_n>`` tokens produced in reversible mode (vault-backed)."""
        return restore_tokens(text, self.vault.mapping(session_id))

    def unmask_stream(self, session_id: str) -> StreamDeanonymizer:
        """Streaming counterpart of :meth:`unmask` for a vault session."""
        return StreamDeanonymizer(self.vault.mapping(session_id))

    def anonymize(self, text: str, session_map: dict[str, str] | None = None) -> tuple[str, dict[str, str]]:
        """Stateless reversible masking: returns ``(text, session_map)``.

        ``session_map`` (token -> original) is owned by the caller, so it works
        across replicas and processes. Pass the same map again to keep token
        numbering consistent across turns.
        """
        fwd = dict(session_map or {})
        rev = {v: k for k, v in fwd.items()}
        if not self.mask_pii_enabled or not text:
            return text, fwd
        parts, last = [], 0
        for m in self.detect(text):
            parts.append(text[last : m.start])
            other = self.mode_by_entity.get(m.entity)
            if other and other != "reversible":  # this entity is configured not to be restorable
                parts.append(self._replacement(m, None, other))
            else:
                parts.append(assign_token(fwd, rev, m.entity, m.text))
            last = m.end
        parts.append(text[last:])
        return "".join(parts), fwd

    @staticmethod
    def deanonymize(text: str, session_map: dict[str, str]) -> str:
        return restore_tokens(text, session_map)

    @staticmethod
    def deanonymize_stream(session_map: dict[str, str]) -> StreamDeanonymizer:
        """Streaming counterpart of :meth:`deanonymize`: ``feed()`` each chunk, then ``flush()``."""
        return StreamDeanonymizer(session_map)


@dataclass
class ScanResult:
    """Result of :meth:`KawalLM.scan` — safety verdict and sanitized text in one object."""

    is_blocked: bool
    violation_reason: str
    sanitized_text: str
    violations: dict[str, float] = field(default_factory=dict)
    flagged: dict[str, float] = field(default_factory=dict)
    entities: list[PIIMatch] = field(default_factory=list)
    session_id: str | None = None

    @property
    def is_safe(self) -> bool:
        return not self.is_blocked

    @property
    def pii_found(self) -> bool:
        return bool(self.entities)


class KawalLM(KawalLMEngine):
    """High-level API.

    >>> guard = KawalLM()
    >>> r = guard.scan("NIK saya 3171011501900001")
    >>> r.is_blocked, r.sanitized_text
    (False, 'NIK saya <ID_NIK>')
    """

    def __init__(
        self,
        mask_pii: bool = True,
        block_safety: bool = True,
        mode: str = "token",
        validate_wilayah: bool = True,
        **kwargs,
    ) -> None:
        kwargs.setdefault("block_violations", block_safety)
        super().__init__(mask_pii=mask_pii, mode=mode, validate_wilayah=validate_wilayah, **kwargs)

    def scan(self, text: str, session_id: str | None = None, context: Mapping[str, object] | None = None) -> ScanResult:
        """Safety check + PII masking in one call.

        ``sanitized_text`` is always produced (useful for logging), even when
        the request is blocked. When the engine has an ``audit`` log, one event is
        recorded (counts and categories only); ``context`` adds caller-supplied
        identifiers such as ``{"app": "hr-bot"}``.
        """
        safety = self.scanner.scan(text)
        blocked = self.block_violations and not safety.safe
        masked = self.mask(text, session_id)
        if self.audit:
            self.audit.record(
                "scan",
                entities=(m.entity for m in masked.entities),
                categories=safety.violations if blocked else (),
                blocked=blocked,
                context=context,
            )
        return ScanResult(
            is_blocked=blocked,
            violation_reason=safety.reason if blocked else "",
            sanitized_text=masked.text,
            violations=safety.violations,
            flagged=safety.flagged,
            entities=masked.entities,
            session_id=masked.session_id,
        )


_default: KawalLMEngine | None = None


def _engine() -> KawalLMEngine:
    global _default
    if _default is None:
        _default = KawalLMEngine()
    return _default


def mask(text: str) -> str:
    """Convenience: mask PII with the default engine (token mode)."""
    return _engine().mask_pii(text)


def check_safety(text: str) -> tuple[bool, str]:
    """Convenience: run the default safety scanner."""
    return _engine().check_safety(text)
