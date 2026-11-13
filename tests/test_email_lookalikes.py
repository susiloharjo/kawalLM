"""Package references (CDN / npm) look like e-mail addresses but are not personal data."""

import pytest

from kawallm import KawalLM
from kawallm.pii import detect_pii


@pytest.mark.parametrize(
    "text",
    [
        '<script src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"></script>',
        "https://unpkg.com/react@18.2.0/umd/react.production.min.js",
        "npm i @angular/core@17.0.0",
        'import x from "https://esm.sh/@scope/pkg@1.2.3"',
        "https://cdn.jsdelivr.net/npm/vue@3.4.0",
        "https://cdn.jsdelivr.net/npm/pkg@1.2.3-beta/dist/index.js",
        "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js?v=a@2.0",
        "pip install kawallm==0.3.1 dan lodash@latest",
    ],
)
def test_package_versions_are_not_masked_as_email(text):
    assert not [m for m in detect_pii(text) if m.entity == "EMAIL"]
    assert KawalLM().scan(text).sanitized_text == text


@pytest.mark.parametrize(
    "text,expected",
    [
        ("kontak budi@contoh.co.id", "kontak <EMAIL>"),
        ("budi.santoso+tag@mail.example.com.", "<EMAIL>."),
        ("a@b.co", "<EMAIL>"),
        ("cc: ani_01@kantor.go.id, rina@x.org", "cc: <EMAIL>, <EMAIL>"),
        (
            "https://cdn.example.com/npm/lodash@4.17.21 hubungi budi@contoh.co.id",
            "https://cdn.example.com/npm/lodash@4.17.21 hubungi <EMAIL>",
        ),
    ],
)
def test_real_addresses_are_still_masked(text, expected):
    assert KawalLM().scan(text).sanitized_text == expected
