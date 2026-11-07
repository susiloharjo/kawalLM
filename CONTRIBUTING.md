# Panduan Kontribusi KawalLM

Terima kasih sudah mau berkontribusi! 🙏 Panduan ini dalam Bahasa Indonesia; PR/issue dalam Bahasa Inggris juga diterima.

## Aturan emas: jangan pernah pakai data pribadi asli

Semua test, issue, dan contoh **wajib** memakai data sintetis:

```python
from kawallm import synthetic

synthetic.nik(seed=1)  # NIK valid secara struktur, kode wilayah asli, orang fiktif
synthetic.npwp(seed=1)  # NPWP dengan checksum valid
synthetic.phone(seed=1)
synthetic.bpjs_kesehatan(seed=1)
```

PR yang berisi NIK/NPWP/no. HP milik orang sungguhan akan ditutup dan history-nya dibersihkan.

## Setup

```bash
git clone https://github.com/<you>/KawalLM && cd KawalLM
uv venv && uv pip install -e ".[dev,litellm,presidio]"
uv run pytest --cov
uvx ruff check . && uvx ruff format .
```

## 1. Menambah kamus (paling mudah — `good first issue`)

File ada di `src/kawallm/safety/words/`. Format:

```json
{
  "category": "TOXIC_SLANG",
  "language": "jv",
  "description": "Umpatan Bahasa Jawa",
  "default_weight": 1.0,
  "contributors": ["github-username"],
  "terms": [
    {"term": "jancuk"},
    {"term": "asem", "weight": 0.5},
    {"term": "anjing", "prefix": true}
  ]
}
```

- **Kategori**: `TOXIC_SLANG`, `JUDOL_PINJOL`, `SARA_HATE_SPEECH`.
- **Bobot**: `1.0` bila istilah hampir selalu bermasalah. `0.5`/`0.3` bila punya arti netral (mis. *asu* = anjing, *asem* = buah, *zeus* = dewa Yunani). Kategori baru memblokir saat jumlah bobot ≥ 1.0.
- **`prefix: true`** agar juga cocok dengan bentuk berimbuhan (`anjingnya`). Gunakan hati-hati.
- Tidak perlu menulis varian leetspeak (`g4c0r`) atau spasi (`s l o t`) — normalizer menanganinya.
- Bahasa daerah baru → buat file baru `regional_<bahasa>.json`; otomatis termuat.
- Tambahkan contoh positif & negatif ke `tests/test_safety.py`.

## 2. Menambah / memperbaiki detektor PII

Detektor ada di `src/kawallm/pii/`. Prinsip:

1. **Validasi, bukan regex mentah.** Nomor yang gagal validasi tidak boleh dimaskir (mencegah false positive resi/barcode).
2. Bila format tidak punya checksum/struktur khas, **wajib keyword proximity** (lihat `bpjs.py`, `bank.py`).
3. Kembalikan `PIIMatch` dan daftarkan di `DETECTORS` (`pii/__init__.py`) serta `PRIORITY` (`pii/base.py`).
4. Sertakan sumber resmi format (peraturan, dokumentasi instansi) di docstring.

## 3. Rule jailbreak / SARA

`safety/jailbreak.py` dan `safety/incitement.py`. Regex dijalankan pada teks yang sudah dinormalisasi (huruf kecil, tanpa tanda baca). Setiap rule baru wajib punya test **false positive** (kalimat wajar yang mirip tapi tidak boleh diblokir).

## 4. Update kode wilayah Kemendagri

```bash
git clone --depth 1 https://github.com/cahyadsn/wilayah /tmp/wilayah
python scripts/build_wilayah.py /tmp/wilayah/db
```

## Data pihak ketiga

Hanya data berlisensi kompatibel Apache-2.0 (MIT, BSD, Apache, CC0, CC-BY) yang boleh dibundel, dan wajib dicatat di `NOTICE`. Data non-komersial (CC BY-NC) **tidak boleh** masuk repo — sediakan script import seperti `scripts/import_abusive_lexicon.py`.

## Checklist PR

- [ ] Test hijau, coverage ≥ 90%
- [ ] Ruff bersih
- [ ] Data sintetis saja
- [ ] Benchmark tidak memburuk (bila menyentuh hot path)

## Kode etik

Kamus berisi kata kasar dan ujaran kebencian **semata-mata untuk moderasi**. Diskusi di issue/PR tetap profesional dan saling menghormati.
