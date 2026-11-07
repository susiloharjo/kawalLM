"""IP addresses (IPv4 and IPv6) as ``IP_ADDRESS``.

An IP address can identify a person or reveal an internal network, so it is masked like any other identifier.
Candidates are validated with :mod:`ipaddress`, which rejects things that merely look like one:

* IPv4 octets above 255 and leading zeros (``10.0.19045.2965`` build numbers, ``010.080.199.027``);
* IPv6 candidates that are not valid compressed/full forms, MAC addresses, clock times, and ``Foo::Bar``
  style identifiers (a candidate needs at least one digit);
* version strings written as ``v1.2.3.4`` / ``versi 1.2.3.4`` / ``version 1.2.3.4``.

Drop the entity with ``entities=`` when IPs should pass through (for example in a network-ops assistant).
"""

from __future__ import annotations

import ipaddress
import re

from .base import PIIMatch

# No leading lookbehind (it defeats the regex engine's first-character scan); the boundary is checked in Python.
IPV4_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}(?!\d)")
IPV6_RE = re.compile(r"[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Fa-f:])")
_VERSION_BEFORE = re.compile(r"(?<![a-z])(?:v|ver|versi|version)\s*$")  # whole word, so "server" does not count


def _starts_inside_token(text: str, start: int) -> bool:
    return start > 0 and (text[start - 1].isalnum() or text[start - 1] in "._:")


def find_ip(text: str) -> list[PIIMatch]:
    out = []
    for m in IPV4_RE.finditer(text):
        if _starts_inside_token(text, m.start()):
            continue
        if _VERSION_BEFORE.search(text[max(0, m.start() - 8) : m.start()].lower()):
            continue
        try:
            ipaddress.IPv4Address(m.group())
        except ValueError:
            continue
        out.append(PIIMatch("IP_ADDRESS", m.start(), m.end(), m.group(), 0.9, {"version": 4}))
    if "::" in text or text.count(":") >= 7:
        for m in IPV6_RE.finditer(text):
            value = m.group()
            if _starts_inside_token(text, m.start()) or not any(ch.isdigit() for ch in value):
                continue
            try:
                ipaddress.IPv6Address(value)
            except ValueError:
                continue
            out.append(PIIMatch("IP_ADDRESS", m.start(), m.end(), value, 0.9, {"version": 6}))
    return out
