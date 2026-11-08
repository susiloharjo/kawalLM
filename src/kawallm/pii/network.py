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

# Starts with literal '.' so the C regex engine uses fast byte search (memchr) instead of scanning every digit.
IPV4_RE = re.compile(r"\.(?<=\d.)\d{1,3}\.\d{1,3}\.\d{1,3}(?!\d)")
IPV6_RE = re.compile(r"[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Fa-f:])")
_VERSION_BEFORE = re.compile(r"(?<![a-z])(?:v|ver|versi|version)\s*$")  # whole word, so "server" does not count


def _starts_inside_token(text: str, start: int) -> bool:
    return start > 0 and (text[start - 1].isalnum() or text[start - 1] in "._:")


def find_ip(text: str) -> list[PIIMatch]:
    out = []
    if "." in text:
        for m in IPV4_RE.finditer(text):
            start = m.start()
            while start > 0 and text[start - 1].isdigit():
                start -= 1
            if not (1 <= m.start() - start <= 3) or _starts_inside_token(text, start):
                continue
            if _VERSION_BEFORE.search(text[max(0, start - 8) : start].lower()):
                continue
            val = text[start : m.end()]
            try:
                ipaddress.IPv4Address(val)
            except ValueError:
                continue
            out.append(PIIMatch("IP_ADDRESS", start, m.end(), val, 0.9, {"version": 4}))
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
