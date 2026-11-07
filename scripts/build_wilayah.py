"""Rebuild src/kawallm/data/wilayah_kemendagri.json from cahyadsn/wilayah (MIT).

    git clone --depth 1 https://github.com/cahyadsn/wilayah /tmp/wilayah
    python scripts/build_wilayah.py /tmp/wilayah/db

Takes the union of every archived decree plus the current one, because a NIK
keeps the kecamatan code that was valid when it was issued. Names come from the
newest decree that has the code. Run this when Kemendagri publishes a new
decree and open a PR with the regenerated JSON.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROW = re.compile(r"\('(\d{2}(?:\.\d{2}){0,2})'\s*,\s*'((?:[^'\\]|\\.|'')*)'\)")
OUT = Path(__file__).resolve().parents[1] / "src/kawallm/data/wilayah_kemendagri.json"


def main(db: str) -> None:
    db_dir = Path(db)
    archive = sorted((db_dir / "archive").glob("wilayah_20*.sql"))  # oldest first
    files = [*archive, db_dir / "wilayah.sql"]
    prov: dict[str, str] = {}
    kab: dict[str, str] = {}
    kec: dict[str, str] = {}
    current: set[str] = set()
    for f in files:
        for kode, nama in ROW.findall(f.read_text(encoding="utf-8", errors="ignore")):
            k = kode.replace(".", "")
            nama = nama.replace("\\'", "'").replace("''", "'").strip()
            {2: prov, 4: kab, 6: kec}[len(k)][k] = nama
            if f.name == "wilayah.sql" and len(k) == 6:
                current.add(k)
    data = {
        "source": "cahyadsn/wilayah (MIT) — Kepmendagri, union of: " + ", ".join(f.name for f in files),
        "provinsi": prov,
        "kabkota": kab,
        "kecamatan": kec,
        "kecamatan_historical_only": sorted(set(kec) - current),
    }
    OUT.write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    print(
        f"provinsi={len(prov)} kabkota={len(kab)} kecamatan={len(kec)} (historical-only={len(set(kec) - current)}) -> {OUT}"
    )


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/wilayah/db")
