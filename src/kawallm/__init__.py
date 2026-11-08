"""KawalLM — low-latency guardrail engine for Indonesian PII (UU PDP) and content safety."""

from .audit import AuditEvent, AuditLog, JsonlFileSink, logging_sink
from .core import (
    KawalLM,
    KawalLMEngine,
    MaskResult,
    ScanResult,
    Vault,
    VaultBackend,
    check_safety,
    mask,
    restore_tokens,
)
from .pii import PIIMatch, detect_pii, parse_nik, validate_nik, validate_npwp
from .placeholders import StreamDeanonymizer
from .safety import SafetyResult, SafetyScanner

__version__ = "0.2.1"

__all__ = [
    "AuditEvent",
    "AuditLog",
    "JsonlFileSink",
    "logging_sink",
    "KawalLM",
    "ScanResult",
    "restore_tokens",
    "StreamDeanonymizer",
    "KawalLMEngine",
    "MaskResult",
    "Vault",
    "VaultBackend",
    "mask",
    "check_safety",
    "detect_pii",
    "parse_nik",
    "validate_nik",
    "validate_npwp",
    "PIIMatch",
    "SafetyScanner",
    "SafetyResult",
    "__version__",
]
