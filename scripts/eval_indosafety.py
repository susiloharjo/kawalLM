"""Evaluate KawalLM's safety scanner against the IndoSafety dataset.

IndoSafety (Apache-2.0, EMNLP 2025) — https://github.com/falensiazmi/IndoSafety
contains *harmful questions* in Indonesian, colloquial Indonesian, Javanese,
Sundanese and Minang. KawalLM's dictionary/rule layer is designed for
promotion spam, slurs and prompt injection, not for judging whether a question
is harmful, so expect low recall on most risk areas. The numbers show where
the Sprint-4 classifier is needed.

    git clone --depth 1 https://github.com/falensiazmi/IndoSafety /tmp/IndoSafety
    pip install pandas openpyxl
    python scripts/eval_indosafety.py /tmp/IndoSafety/dataset/IndoSafety-Eval-1.xlsx
"""

from __future__ import annotations

import argparse

import pandas as pd

from kawallm.safety import SafetyScanner


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("xlsx", nargs="+")
    ap.add_argument("--include-toxic", action="store_true", help="count TOXIC_SLANG as a block")
    a = ap.parse_args()

    cats = ["JUDOL_PINJOL", "SARA_HATE_SPEECH", "JAILBREAK"] + (["TOXIC_SLANG"] if a.include_toxic else [])
    s = SafetyScanner(block_categories=cats)
    df = pd.concat([pd.read_excel(p) for p in a.xlsx], ignore_index=True)
    df["blocked"] = df["prompt"].fillna("").astype(str).map(lambda t: not s.scan(t).safe)
    df["flagged"] = df["prompt"].fillna("").astype(str).map(lambda t: bool(s.scan(t).hits))

    print(f"prompts: {len(df)}  blocked: {df.blocked.mean():.1%}  any-hit: {df.flagged.mean():.1%}\n")
    by = df.groupby("types_of_harm")[["blocked", "flagged"]].mean().sort_values("blocked", ascending=False)
    print((by * 100).round(1).to_string())


if __name__ == "__main__":
    main()
