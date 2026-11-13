"""IP addresses (IPv4 and IPv6) as ``IP_ADDRESS``.

An IP address can identify a person or reveal an internal network, so it is masked like any other identifier.
Candidates are validated with :mod:`ipaddress`, which rejects things that merely look like one:

* IPv4 octets above 255 and leading zeros (``10.0.19045.2965`` build numbers, ``010.080.199.027``);
* IPv6 candidates that are not valid compressed/full forms, MAC addresses, clock times, and ``Foo::Bar``
  style identifiers (a candidate needs at least one digit);
* version strings: ``v1.2.3.4`` / ``versi 1.2.3.4`` / ``kernel 6.1.0.13`` / ``build 1.2.3.4`` (a version word before),
  ``pkg==1.2.3.4`` / ``>=1.2.3.4`` / ``^1.2.3.4`` (a version pin before) and ``1.2.3.4-rc1`` (a pre-release after).

Addresses that identify nobody are never reported: loopback (``127.0.0.1``, ``::1``), the unspecified address
(``0.0.0.0``), link-local (``169.254.x.x``, ``fe80::``), multicast, broadcast, the documentation ranges and the
well-known public DNS resolvers (``1.1.1.1``, ``8.8.8.8``, ``9.9.9.9``, ...). Private
networks (``10.x``, ``192.168.x``, ``172.16-31.x``, ``fc00::/7``) are not personal data but reveal an internal network,
so they are left alone by default (``ip_scope="public"``: only globally routable addresses are masked);
``ip_scope="all"`` also masks them, for deployments where internal topology must not reach the model.

Drop the entity with ``entities=`` when IPs should pass through (for example in a network-ops assistant).
"""

from __future__ import annotations

import ipaddress
import re

from .base import PIIMatch

# Starts with literal '.' so the C regex engine uses fast byte search (memchr) instead of scanning every digit.
IPV4_RE = re.compile(r"\.(?<=\d.)\d{1,3}\.\d{1,3}\.\d{1,3}(?!\d)")
IPV6_RE = re.compile(r"[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Fa-f:])")
# Whole word, so "server" does not count.
_VERSION_BEFORE = re.compile(r"(?<![a-z])(?:v|ver|versi|version|build|kernel|release|rilis|rev|revision|firmware)\s*$")
_PIN_BEFORE = re.compile(r"(?:==|>=|<=|~=|~>|!=|\^|~)\s*$")
_PRERELEASE_AFTER = re.compile(r"[-+][A-Za-z]")


def _starts_inside_token(text: str, start: int) -> bool:
    return start > 0 and (text[start - 1].isalnum() or text[start - 1] in "._:")


IP_SCOPES = ("public", "all")
_DOCUMENTATION = tuple(
    ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)
_BROADCAST = ipaddress.IPv4Address("255.255.255.255")

# Public DNS resolvers everybody uses: shared infrastructure, not data about a person, so never masked.
# (Cloudflare, Google, Quad9, OpenDNS, AdGuard, CleanBrowsing, Yandex, Alibaba, Tencent, Baidu, 114DNS, Verisign,
# Comodo, Level3, DNS.WATCH, Neustar, SafeDNS, Alternate DNS.)
WELL_KNOWN_DNS = frozenset(
    ipaddress.ip_address(a)
    for a in (
        "1.1.1.1 1.0.0.1 1.1.1.2 1.0.0.2 1.1.1.3 1.0.0.3 8.8.8.8 8.8.4.4 9.9.9.9 9.9.9.10 9.9.9.11 "
        "149.112.112.112 149.112.112.10 149.112.112.11 208.67.222.222 208.67.220.220 208.67.222.220 208.67.220.222 "
        "94.140.14.14 94.140.15.15 185.228.168.9 185.228.169.9 77.88.8.8 77.88.8.1 223.5.5.5 223.6.6.6 119.29.29.29 "
        "180.76.76.76 114.114.114.114 114.114.115.115 64.6.64.6 64.6.65.6 8.26.56.26 8.20.247.20 4.2.2.1 4.2.2.2 "
        "4.2.2.3 4.2.2.4 4.2.2.5 4.2.2.6 84.200.69.80 84.200.70.40 156.154.70.1 156.154.71.1 195.46.39.39 "
        "195.46.39.40 76.76.19.19 76.223.122.150 "
        "2606:4700:4700::1111 2606:4700:4700::1001 2606:4700:4700::1112 2606:4700:4700::1002 2606:4700:4700::1113 "
        "2606:4700:4700::1003 2001:4860:4860::8888 2001:4860:4860::8844 2620:fe::fe 2620:fe::9 2620:fe::fe:10 "
        "2620:fe::fe:11 2620:119:35::35 2620:119:53::53 2a10:50c0::ad1:ff 2a10:50c0::ad2:ff"
    ).split()
)


def _reportable(addr: ipaddress.IPv4Address | ipaddress.IPv6Address, scope: str) -> bool:
    """Whether an address is worth masking under ``scope`` ("public": global only; "all": all but the never-sensitive)."""
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if addr.is_loopback or addr.is_unspecified or addr.is_link_local or addr.is_multicast or addr == _BROADCAST:
        return False
    if addr in WELL_KNOWN_DNS or any(addr in net for net in _DOCUMENTATION if net.version == addr.version):
        return False
    return not (scope == "public" and addr.is_private)


def find_ip(text: str, scope: str = "public") -> list[PIIMatch]:
    out = []
    if "." in text:
        for m in IPV4_RE.finditer(text):
            start = m.start()
            while start > 0 and text[start - 1].isdigit():
                start -= 1
            if not (1 <= m.start() - start <= 3) or _starts_inside_token(text, start):
                continue
            before = text[max(0, start - 12) : start].lower()
            if _VERSION_BEFORE.search(before) or _PIN_BEFORE.search(before):
                continue
            if _PRERELEASE_AFTER.match(text, m.end()):
                continue
            val = text[start : m.end()]
            try:
                addr4 = ipaddress.IPv4Address(val)
            except ValueError:
                continue
            if _reportable(addr4, scope):
                out.append(PIIMatch("IP_ADDRESS", start, m.end(), val, 0.9, {"version": 4}))
    if "::" in text or text.count(":") >= 7:
        for m in IPV6_RE.finditer(text):
            value = m.group()
            if _starts_inside_token(text, m.start()) or not any(ch.isdigit() for ch in value):
                continue
            try:
                addr6 = ipaddress.IPv6Address(value)
            except ValueError:
                continue
            if _reportable(addr6, scope):
                out.append(PIIMatch("IP_ADDRESS", m.start(), m.end(), value, 0.9, {"version": 6}))
    return out
