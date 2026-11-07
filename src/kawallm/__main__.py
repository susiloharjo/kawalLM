"""CLI: ``python -m kawallm "teks"`` or ``echo teks | kawallm``."""

from __future__ import annotations

import argparse
import json
import sys

from .core import KawalLMEngine


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="kawallm", description="Scan & mask Indonesian PII / unsafe content.")
    p.add_argument("text", nargs="?", help="text to scan (default: stdin)")
    p.add_argument("--mode", default="token", choices=["token", "redact", "partial", "reversible"])
    p.add_argument("--json", action="store_true", help="print full JSON report")
    a = p.parse_args(argv)
    text = a.text if a.text is not None else sys.stdin.read()
    eng = KawalLMEngine(mode=a.mode)
    safety = eng.scan_safety(text)
    masked = eng.mask(text)
    if a.json:
        print(
            json.dumps(
                {
                    "safe": safety.safe,
                    "violations": safety.violations,
                    "flagged": safety.flagged,
                    "masked": masked.text,
                    "entities": [{"entity": m.entity, "start": m.start, "end": m.end} for m in masked.entities],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        if not safety.safe:
            print(f"BLOCK: {safety.reason}", file=sys.stderr)
        print(masked.text)
    return 0 if safety.safe else 2


if __name__ == "__main__":
    raise SystemExit(main())
