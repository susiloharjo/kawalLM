# Panduan Kontribusi KawalLM

Terima kasih sudah mau berkontribusi! 🙏 Panduan ini dalam Bahasa Indonesia; PR/issue dalam Bahasa Inggris juga diterima.

## Yuk ikut bangun KawalLM

KawalLM adalah guardrail open-source untuk kepatuhan UU PDP di infrastruktur AI Indonesia. Kualitasnya bergantung pada orang yang paham konteks lokal: penutur bahasa daerah, praktisi keamanan, engineer data, dan siapa pun yang pernah kesal karena guardrail global tidak mengerti NIK atau "slot gacor". **Kamu tidak perlu paham ML untuk membantu.** Banyak kontribusi paling berharga hanya berupa JSON atau satu kalimat uji.

Mulai dalam 10 menit:

1. Clone repo dan siapkan lingkungan (lihat [Setup](#setup)), lalu `uv run pytest` supaya yakin semuanya hijau.
2. Pilih satu item dari tabel di bawah. Untuk yang bertanda 🟢, kamu bisa langsung buka PR tanpa diskusi.
3. Untuk perubahan besar (🟡/🔴), buka issue dulu supaya arahnya sama sebelum kamu menulis banyak kode.
4. Buka PR kecil dan fokus. Satu PR, satu hal.

### Yang paling dibutuhkan

| | Apa | Kenapa penting | Di mana | Cara membuktikan |
|---|---|---|---|---|
| 🟢 | **Kamus bahasa daerah**: verifikasi isi Jawa, Sunda, Batak, Minang, Sulawesi (masih seed) dan tambah bahasa lain (Bali, Bugis, Madura, Aceh, Betawi, dll.) | Penutur asli satu-satunya yang bisa menilai mana kata kasar, mana kata biasa | `src/kawallm/safety/words/regional_*.json` | Contoh positif dan negatif di `tests/test_safety.py` |
| 🟢 | **Kalimat wajar untuk eval false positive** | Target kita FP < 1%, tapi set ujinya baru ~100 kalimat buatan maintainer. Makin beragam makin jujur | `tests/data/benign_id.txt` | `uv run pytest tests/test_benign.py` |
| 🟢 | **Laporkan false positive / false negative** (kalimat sah yang terblokir, atau spam judol/pinjol yang lolos) | Setiap laporan jadi test regresi | Buka issue (template tersedia) | Sertakan teks sintetis, jangan data asli |
| 🟢 | **Panjang rekening bank** yang belum ada (sekarang 19 bank) | Rekening hanya dimaskir kalau panjangnya cocok dengan banknya | `src/kawallm/pii/bank.py` | Cantumkan sumber resmi di docstring + test |
| 🟢 | **Dokumentasi**: README versi Inggris, contoh pemakaian, perbaikan typo | Saat ini hampir semua dokumen berbahasa Indonesia, sehingga sulit ditemukan engineer di luar Indonesia | `README.md`, `docs/` | PR cukup berisi teks |
| 🟡 | **Perketat validasi SIM, NISN, paspor**: sekarang hanya kata kunci + panjang karena tidak ada checksum publik. Tambah identitas lain (mis. NUPTK, nomor KTP-el lama, KITAS) | Makin spesifik makin sedikit false positive | `src/kawallm/pii/identity.py` | Sumber resmi format di docstring + test false positive |
| 🟡 | **Audit log** untuk kebutuhan audit UU PDP: hanya kategori, jenis entitas, dan jumlah, tanpa nilai PII | Persona enterprise membutuhkan jejak audit | `src/kawallm/integrations/litellm.py` dan `core.py` | Test bahwa log tidak pernah memuat nilai asli |
| 🟡 | **Vault reversible yang bisa dipasang (Redis dsb.)** | Vault sekarang in-memory per proses, jadi tidak jalan lintas replica | `Vault` di `src/kawallm/core.py` | Antarmuka yang sama dengan `Vault` + test konkurensi |
| 🟡 | **Integrasi lain** (usulan: LangChain, Haystack, Flask/Django middleware) | Memperluas tempat KawalLM bisa dipasang | `src/kawallm/integrations/` | Import tetap lazy (extras), tidak menambah dependency core |
| 🟡 | **Cakupan test** `integrations/presidio.py` (sekitar 82%) | Gate CI kita 90% total | `tests/` | `uv run pytest --cov` |
| 🔴 | **Classifier semantik (ONNX)** untuk pertanyaan berbahaya | Dictionary + rule hanya menangkap 0,3% dari dataset IndoSafety; ini batas produk terbesar | Belum ada modul; diskusikan di issue | Eval dengan `scripts/eval_indosafety.py`, tetap CPU-only dan p95 terjaga |

Pertanyaan terbuka yang butuh pendapat kamu (komentar di issue): apakah classifier sebaiknya fine-tune sendiri atau memakai model terbuka yang di-distill (IndoPII Mini, SEALGuard)? Siapa yang mau menjadi reviewer penutur asli untuk tiap bahasa daerah?

### Prinsip yang membuat KawalLM berbeda

Pegang ini saat berkontribusi, karena PR yang melanggarnya akan diminta direvisi:

- **Deterministik dan lokal.** Tanpa network call, tanpa GPU, tanpa telemetry.
- **Validasi, bukan regex mentah.** Nomor yang gagal validasi tidak boleh dimaskir.
- **Kurangi false positive dulu.** Memblokir kalimat sah lebih merusak kepercayaan daripada melewatkan satu kasus ambigu.
- **Cepat.** p95 ≤ 5 ms untuk 1.000 kata. Jalankan `python benchmarks/bench_latency.py` kalau menyentuh hot path.
- **Hanya data sintetis.** Lihat aturan emas di bawah.

### Ngobrol dulu

Belum yakin harus mulai dari mana? Buka issue dengan template *feature request* dan ceritakan latar belakang serta waktu luangmu, nanti kita carikan tugas yang cocok. Kontribusi sekecil satu kata di kamus atau satu kalimat di eval set tetap dihitung, dan kamu bisa mencantumkan username GitHub-mu di field `contributors` pada file kamus.

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
