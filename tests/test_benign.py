"""False-positive guard: ordinary Indonesian text must pass untouched.

``tests/data/benign_id.txt`` holds synthetic benign sentences, including tricky ones (resi, barcode,
"slot waktu", "depo logistik", "zeus", educational text about judi online, ...). PRD target: < 1% affected.
"""

from pathlib import Path

import pytest

from kawallm import KawalLM

DATA = Path(__file__).parent / "data" / "benign_id.txt"
SENTENCES = [
    line.strip() for line in DATA.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")
]


@pytest.fixture(scope="module")
def guard():
    return KawalLM()


def test_dataset_is_big_enough():
    assert len(SENTENCES) >= 100


def test_false_positive_rate_under_one_percent(guard):
    bad = []
    for text in SENTENCES:
        r = guard.scan(text)
        if r.is_blocked or r.entities or r.sanitized_text != text:
            bad.append((text, r.violation_reason, [e.entity for e in r.entities]))
    rate = len(bad) / len(SENTENCES)
    assert rate < 0.01, f"false positive rate {rate:.1%}: {bad}"


@pytest.mark.parametrize("text", SENTENCES)
def test_each_benign_sentence_passes_untouched(guard, text):
    r = guard.scan(text)
    assert not r.is_blocked, r.violation_reason
    assert r.sanitized_text == text
