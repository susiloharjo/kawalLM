"""Release guard: docs must not fall behind the code.

These checks run in CI and in the publish workflow, so a release (or any push to main)
fails when a new entity is missing from the README or the version has no CHANGELOG entry.
"""

from pathlib import Path

import kawallm
from kawallm.pii.base import PRIORITY

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")
CHANGELOG = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")


def test_every_entity_is_listed_in_readme():
    emitted = set(PRIORITY)  # every entity a detector can emit (ID_BPJS is only a detector key)
    missing = sorted(e for e in emitted if f"`{e}`" not in README)
    assert not missing, f"README.md 'Entitas' section is missing: {missing}"


def test_every_dictionary_language_file_is_documented():
    words = (ROOT / "src" / "kawallm" / "safety" / "words").glob("*.json")
    # categories are what users configure; each one must appear in the README
    import json

    categories = {json.loads(p.read_text(encoding="utf-8"))["category"] for p in words}
    missing = sorted(c for c in categories if c not in README)
    assert not missing, f"README.md does not mention categories: {missing}"


def test_changelog_has_entry_for_current_version():
    assert f"## [{kawallm.__version__}]" in CHANGELOG, (
        f"CHANGELOG.md needs a '## [{kawallm.__version__}]' section before releasing this version"
    )


def test_readme_install_command_matches_package_name():
    assert "pip install kawallm" in README
