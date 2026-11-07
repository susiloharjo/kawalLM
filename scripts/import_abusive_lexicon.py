"""Convert Okky Ibrohim's abusive-word list into a LOCAL KawalLM dictionary.

Source: https://github.com/okkyibrohim/id-multi-label-hate-speech-and-abusive-language-detection
License: CC BY-NC-SA 4.0 (NON-COMMERCIAL). For that reason it is NOT bundled in
KawalLM (Apache-2.0). This script lets you build it for your own,
non-commercial use; the output must not be committed to this repo.

    git clone --depth 1 https://github.com/okkyibrohim/id-multi-label-hate-speech-and-abusive-language-detection /tmp/okky
    python scripts/import_abusive_lexicon.py /tmp/okky/abusive.csv local_abusive.json
    # then: KawalLMEngine(extra_dictionaries=["local_abusive.json"])
"""

from __future__ import annotations

import csv
import json
import sys


def main(src: str, dst: str) -> None:
    with open(src, encoding="utf-8", errors="ignore") as f:
        rows = [r[0].strip() for r in csv.reader(f) if r and r[0].strip() and r[0].strip().upper() != "ABUSIVE"]
    terms = sorted(set(rows))
    json.dump(
        {
            "category": "TOXIC_SLANG",
            "description": "Imported from okkyibrohim abusive.csv (CC BY-NC-SA 4.0) — local use only, do not redistribute.",
            "default_weight": 1.0,
            "terms": terms,
        },
        open(dst, "w", encoding="utf-8"),
        ensure_ascii=False,
        indent=1,
    )
    print(f"{len(terms)} terms -> {dst}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
