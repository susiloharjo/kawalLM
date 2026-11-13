"""IP scope: only public addresses are masked by default; private networks need ``ip_scope="all"``."""

import pytest

from kawallm import KawalLM, KawalLMEngine
from kawallm.__main__ import main
from kawallm.pii import detect_pii

NEVER = [
    "127.0.0.1",
    "127.0.1.1",
    "0.0.0.0",
    "169.254.10.20",
    "255.255.255.255",
    "224.0.0.251",
    "192.0.2.10",
    "198.51.100.7",
    "203.0.113.5",
    "::1",
    "fe80::1ff:fe23:4567:890a",
    "2001:db8::ff00:42:8329",
    "ff02::1",
]
PRIVATE = ["10.0.0.1", "192.168.1.20", "172.16.5.4", "172.31.255.1", "fd12:3456:789a::1"]
PUBLIC = ["103.28.12.5", "45.33.32.156", "100.64.0.1", "2a00:1450:4001::68"]
DNS = [
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "208.67.222.222",
    "94.140.14.14",
    "2606:4700:4700::1111",
    "2001:4860:4860::8888",
    "2620:fe::fe",
]


@pytest.mark.parametrize("ip", NEVER)
@pytest.mark.parametrize("scope", ["all", "public"])
def test_addresses_that_identify_nobody_are_never_masked(ip, scope):
    text = f"jalankan di {ip} lalu cek"
    assert KawalLMEngine(ip_scope=scope).mask(text).text == text


@pytest.mark.parametrize("ip", PRIVATE)
def test_private_networks_are_left_alone_by_default_and_masked_for_all_scope(ip):
    text = f"server {ip} down"
    assert KawalLM().scan(text).sanitized_text == text
    assert KawalLMEngine(ip_scope="all").mask(text).text == "server <IP_ADDRESS> down"


@pytest.mark.parametrize("ip", PUBLIC)
@pytest.mark.parametrize("scope", ["all", "public"])
def test_public_addresses_are_masked_in_every_scope(ip, scope):
    assert KawalLMEngine(ip_scope=scope).mask(f"klien {ip} masuk").text == "klien <IP_ADDRESS> masuk"


@pytest.mark.parametrize("ip", DNS)
@pytest.mark.parametrize("scope", ["public", "all"])
def test_well_known_public_dns_resolvers_are_never_masked(ip, scope):
    text = f"set DNS ke {ip} lalu restart"
    assert KawalLMEngine(ip_scope=scope).mask(text).text == text


def test_an_address_next_to_a_dns_resolver_is_still_masked():
    assert KawalLMEngine().mask("DNS 8.8.8.8 dan klien 103.28.12.5").text == "DNS 8.8.8.8 dan klien <IP_ADDRESS>"


def test_ipv4_mapped_ipv6_follows_the_rules_of_its_ipv4_address():
    assert KawalLMEngine().mask("a ::ffff:7f00:1 b").text == "a ::ffff:7f00:1 b"  # 127.0.0.1
    assert KawalLMEngine().mask("a ::ffff:671c:c05 b").text == "a <IP_ADDRESS> b"  # 103.28.12.5
    assert KawalLMEngine().mask("a ::ffff:a00:1 b").text == "a ::ffff:a00:1 b"  # 10.0.0.1
    assert KawalLMEngine(ip_scope="all").mask("a ::ffff:a00:1 b").text == "a <IP_ADDRESS> b"


def test_a_mix_keeps_only_what_the_scope_asks_for():
    text = "db 10.0.0.5, lb 103.28.12.5, lokal 127.0.0.1"
    assert KawalLMEngine().mask(text).text == "db 10.0.0.5, lb <IP_ADDRESS>, lokal 127.0.0.1"
    assert KawalLMEngine(ip_scope="all").mask(text).text == "db <IP_ADDRESS>, lb <IP_ADDRESS>, lokal 127.0.0.1"


def test_detect_pii_and_the_engine_reject_an_unknown_scope():
    with pytest.raises(ValueError, match="ip_scope"):
        detect_pii("halo 8.8.8.8", ip_scope="private")
    with pytest.raises(ValueError, match="ip_scope"):
        KawalLMEngine(ip_scope="none")


def test_litellm_guardrail_accepts_ip_scope():
    pytest.importorskip("litellm")
    from kawallm.integrations.litellm import KawalLMGuardrail

    text = "db 10.0.0.5 dan 103.28.12.5"
    default = KawalLMGuardrail(guardrail_name="k", event_hook=["pre_call"])
    assert default.engine.mask(text).text == "db 10.0.0.5 dan <IP_ADDRESS>"
    wide = KawalLMGuardrail(guardrail_name="k", event_hook=["pre_call"], ip_scope="all")
    assert wide.engine.mask(text).text == "db <IP_ADDRESS> dan <IP_ADDRESS>"


def test_cli_ip_scope(capsys):
    assert main(["db 10.0.0.5 dan 103.28.12.5"]) == 0
    assert capsys.readouterr().out.strip() == "db 10.0.0.5 dan <IP_ADDRESS>"
    assert main(["--ip-scope", "all", "db 10.0.0.5 dan 103.28.12.5"]) == 0
    assert capsys.readouterr().out.strip() == "db <IP_ADDRESS> dan <IP_ADDRESS>"
