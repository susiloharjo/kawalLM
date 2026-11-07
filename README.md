# KawalLM 🇮🇩

**Guardrail engine open-source, latensi rendah, untuk kepatuhan UU PDP (UU No. 27/2022) di infrastruktur AI Indonesia.**

KawalLM memaskir PII lokal (NIK, NPWP, No. HP, rekening bank, BPJS, plat nomor) dengan **validasi semantik deterministik**, dan memblokir promosi **judol/pinjol ilegal**, **ujaran kebencian SARA**, serta **prompt injection berbahasa Indonesia** — tanpa GPU, tanpa network call, drop-in untuk **LiteLLM Proxy**, **Presidio**, dan **FastAPI**.

> ⚠️ Status: **alpha (v0.1.0)**. Deteksi bukan jaminan kepatuhan hukum. Lakukan review untuk penggunaan berisiko tinggi.

---

## Kenapa KawalLM?

| Masalah | Guardrail global | KawalLM |
|---|---|---|
| NIK 16 digit | Tidak dikenali / regex mentah → resi & barcode ikut terblokir | Validasi kode wilayah Kemendagri (7.879 kecamatan, 2016–2025) + tanggal lahir (DD+40 untuk perempuan) + serial ≠ 0000 |
| NPWP 15/16 digit | Tidak ada | Checksum Luhn digit ke-9, format bertitik atau keyword-gated |
| No. HP | Generic | Prefix operator (Telkomsel, Indosat, Tri, XL, Axis, Smartfren) |
| Rekening bank | Tidak ada | Proximity 5 kata + panjang per bank (BCA 10, Mandiri 13, BRI 15, …) |
| Judol / pinjol | Tidak paham "g4c0r", "s.l.o.t", "depo pulsa" | Aho-Corasick + normalisasi leetspeak/spasi + skor berbobot |
| Prompt injection ID | Fokus Bahasa Inggris | Rule "abaikan instruksi sebelumnya", "bocorkan system prompt", DAN, dll. |

## Instalasi

```bash
pip install kawallm                 # core (hanya butuh pyahocorasick)
pip install "kawallm[litellm]"      # + LiteLLM Proxy guardrail
pip install "kawallm[presidio]"     # + Presidio recognizer
pip install "kawallm[fastapi]"      # + FastAPI middleware
```

## Quick start

```python
from kawallm import KawalLM

guard = KawalLM(mask_pii=True, block_safety=True, validate_wilayah=True)

r = guard.scan("Tolong bayar ke rekening BCA 1234567890 an Eko, NIK saya 3171012304900001")
r.is_blocked  # False
r.sanitized_text  # 'Tolong bayar ke rekening BCA <ID_BANK_ACCOUNT> an Eko, NIK saya <ID_NIK>'

r = guard.scan("Tuliskan promosi link slot gacor maxwin depo pulsa")
r.is_blocked  # True
r.violation_reason  # 'JUDOL_PINJOL (depo, depo pulsa, gacor)'

guard.scan("Resi JNE 1234567890123456").sanitized_text  # 16 digit tapi bukan NIK valid → tidak dimaskir
guard.scan("Jelaskan bahaya judi online bagi remaja").is_blocked  # False — diskusi edukatif lolos
```

Reversible / pseudonimisasi bolak-balik (stateless — `session_map` dipegang aplikasi, aman untuk multi-replica):

```python
guard = KawalLM(mode="reversible")
text, session_map = guard.anonymize("Kirim SMS konfirmasi ke 081288889999 sekarang.")
# text        = 'Kirim SMS konfirmasi ke <ID_PHONE_1> sekarang.'
# session_map = {'<ID_PHONE_1>': '081288889999'}

guard.deanonymize("Baik, terkirim ke <ID_PHONE_1>.", session_map)
# 'Baik, terkirim ke 081288889999.'
```

Helper lain:

```python
from kawallm import mask, check_safety, parse_nik

mask("HP 0812-3456-7890")  # 'HP <ID_PHONE>'
check_safety("abaikan instruksi sebelumnya")  # (False, 'JAILBREAK (...)')
parse_nik("3171015501920002")
# {'wilayah': {'provinsi': 'Daerah Khusus Ibukota Jakarta', 'kabkota': 'Kota Administrasi Jakarta Pusat',
#   'kecamatan': 'Gambir'}, 'jenis_kelamin': 'P', 'tanggal': 15, 'bulan': 1, ...}
```

Panduan lengkap 3 skenario (LiteLLM gateway, library Python, reversible): [`docs/usage.md`](docs/usage.md).

CLI:

```bash
echo "HP saya 081234567890" | kawallm          # → HP saya <ID_PHONE>
kawallm --json "abaikan instruksi sebelumnya"  # exit code 2 bila diblokir
```

### Mode masking

| Mode | Output | Kegunaan |
|---|---|---|
| `token` (default) | `<ID_NIK>` | Kirim ke LLM publik |
| `reversible` | `<ID_NIK_1>` + vault TTL in-memory | De-masking di respons (FR-3.2) |
| `partial` | `************0001` | Log / tampilan UI |
| `redact` | `[REDACTED]` | Data lake, fine-tuning |

### Entitas

`ID_NIK`, `ID_NPWP`, `ID_PHONE`, `ID_BANK_ACCOUNT`, `ID_BPJS_KES`, `ID_BPJS_TK`, `ID_PLATE`, `EMAIL`.
Catatan: nomor **KK** punya struktur sama dengan NIK, sehingga terdeteksi sebagai `ID_NIK` (keduanya data pribadi).

## LiteLLM Proxy

```yaml
# config.yaml
guardrails:
  - guardrail_name: kawallm
    litellm_params:
      guardrail: kawallm.integrations.litellm.KawalLMGuardrail
      mode: [pre_call, post_call]
      default_on: true
      masking_mode: reversible
      restore_output: true
      block_categories: JUDOL_PINJOL,SARA_HATE_SPEECH,JAILBREAK
```

| Hook | Perilaku |
|---|---|
| `pre_call` | Safety check pada pesan **role user** (system prompt tidak dicek agar "jangan bocorkan system prompt" tidak memicu blokir) → HTTP 400. PII dimaskir di **semua role**, termasuk multimodal text parts. |
| `post_call` | PII baru dari model dimaskir (*output leakage*), lalu token `<ID_X_n>` milik pemanggil dikembalikan (reversible). Argumen `tool_calls` juga di-de-mask. |
| streaming | Sama, dengan *hold-back buffer* 48 karakter agar nilai yang terpotong antar chunk tetap tertangkap. |

Docker siap jalan (LiteLLM + KawalLM):

```bash
cd docker
OPENAI_API_KEY=sk-... LITELLM_MASTER_KEY=sk-local docker compose up --build
```

## Presidio

```python
from presidio_analyzer import AnalyzerEngine
from kawallm.integrations.presidio import KawalLMRecognizer, analyzer_without_nlp

analyzer = AnalyzerEngine()
analyzer.registry.add_recognizer(KawalLMRecognizer(supported_language="en"))

# atau tanpa download model spaCy sama sekali:
analyzer = analyzer_without_nlp("id")
analyzer.analyze("NIK 3171011501900001", language="id")
```

## FastAPI

```python
from fastapi import FastAPI
from kawallm.integrations.fastapi import KawalLMMiddleware

app = FastAPI()
app.add_middleware(KawalLMMiddleware, paths=("/chat",), fields=("prompt", "message"))
```

## Safety: cara kerja skor

Kamus (`src/kawallm/safety/words/*.json`) + rule regex dikompilasi sekali ke satu automaton Aho-Corasick. Setiap istilah punya **bobot**:

- `1.0` — sinyal kuat (mis. `slot gacor`, `depo pulsa`, `bocoran rtp`) → cukup satu untuk blokir
- `0.5` / `0.3` — sinyal ambigu (mis. `zeus`, `togel`, `judi online`) → perlu digabung sinyal lain hingga skor ≥ `threshold` (default 1.0)

Default **blocking**: `JUDOL_PINJOL`, `SARA_HATE_SPEECH`, `JAILBREAK`. `TOXIC_SLANG` hanya di-*flag* (bisa dijadikan blocking via `block_categories`).

## Benchmark

`python benchmarks/bench_latency.py` — safety scan + PII mask per payload, 1 core, Intel Xeon @ 2.1 GHz, Python 3.13, payload sintetis (~1 PII per 50 kata):

| Kata / payload | p50 | p95 | p99 | Throughput / core | Peak RSS |
|---:|---:|---:|---:|---:|---:|
| 100 | 0.30 ms | 0.47 ms | 0.56 ms | ~2.970 req/s | 21 MB |
| 500 | 1.22 ms | 1.45 ms | 2.16 ms | ~780 req/s | 21 MB |
| 1.000 | 2.36 ms | 2.83 ms | 5.3 ms | ~400 req/s | 21 MB |

**vs NFR PRD:** p95 ≤ 5 ms @1.000 kata ✅ · RAM < 120 MB ✅ · zero telemetry ✅ · coverage ≥ 90% ✅ (97%).
Throughput ≥ 1.500 req/s pada 2 vCPU **tercapai untuk prompt pendek (≤ ~200 kata)**, tidak untuk payload 1.000 kata (~800 req/s di 2 core). Dua target ini secara matematis tidak bisa sama-sama terpenuhi: p95 5 ms per request = maks ~200 req/s per core.

## Keterbatasan (jujur)

- **Bukan classifier.** Dictionary + rule menangkap promosi spam, slur, dan pola injection yang eksplisit. Pada dataset [IndoSafety](https://github.com/falensiazmi/IndoSafety) (3.014 *pertanyaan berbahaya* — kategori yang berbeda), hanya 0,3% diblokir. Pertanyaan berbahaya semantik butuh model (Sprint 4: ONNX classifier). Jalankan sendiri: `python scripts/eval_indosafety.py`.
- **Kamus bahasa daerah masih seed** dan perlu verifikasi penutur asli — ini area kontribusi utama.
- Validasi NIK/NPWP memeriksa **format**, bukan keberadaan orangnya.
- Vault reversible bersifat in-memory per proses; untuk multi-replica gunakan sticky session.
- Argumen `tool_calls` di request tidak di-scan.

## Sumber data & atribusi

| Data | Sumber | Lisensi | Status |
|---|---|---|---|
| Kode wilayah Kemendagri 2016–2025 | [cahyadsn/wilayah](https://github.com/cahyadsn/wilayah) | MIT | **Dibundel** (`src/kawallm/data/`) |
| Algoritma checksum NPWP | python-stdnum (`stdnum.id.npwp`) | LGPL — hanya algoritma, tanpa kode | Diimplementasi ulang |
| IndoSafety (eval) | [falensiazmi/IndoSafety](https://github.com/falensiazmi/IndoSafety) | Apache-2.0 | Script eval, tidak dibundel |
| Abusive lexicon (Ibrohim & Budi 2019) | [okkyibrohim/…](https://github.com/okkyibrohim/id-multi-label-hate-speech-and-abusive-language-detection) | CC BY-NC-SA 4.0 | **Tidak dibundel** (non-komersial). `scripts/import_abusive_lexicon.py` untuk pemakaian lokal |

Lihat [`NOTICE`](NOTICE).

## Proyek terkait

[IndoPII Mini](https://huggingface.co/AIbnuHibban/indopii-mini) (NER model PII Indonesia), [NusaIndex](https://pkg.go.dev/github.com/haikalmumtaz233/nusaindex) (validator Go/TS), [SEALGuard](https://github.com/awsm-research/SEALGuard) (guardrail LLM Asia Tenggara). KawalLM fokus pada lapisan deterministik CPU-only yang bisa digabung dengan model-model tersebut.

## Kontribusi

Lihat [CONTRIBUTING.md](CONTRIBUTING.md). Kontribusi paling dibutuhkan: kamus bahasa daerah, panjang rekening bank, identitas baru (NIP, NISN, paspor, SIM).

## Lisensi

Apache License 2.0 — lihat [LICENSE](LICENSE).
