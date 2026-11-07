# Panduan Penggunaan KawalLM

KawalLM bisa dipakai dengan 3 skenario utama:

| Skenario | Cocok untuk | Cara pasang |
|---|---|---|
| 1. **LiteLLM Proxy (AI Gateway)** | Organisasi / tim: semua trafik AI wajib lewat satu gateway | Satu blok di `config.yaml` LiteLLM |
| 2. **Library Python** | Backend FastAPI, RAG pipeline, pembersihan dokumen sebelum masuk vector DB | `pip install kawallm` |
| 3. **Reversible masking** | Chatbot CS yang perlu menampilkan data asli kembali ke user | `KawalLM(mode="reversible")` |

---

## Skenario 1: LiteLLM Proxy (AI Gateway)

Semua trafik AI dari aplikasi internal lewat LiteLLM Proxy sebelum menyentuh OpenAI, Claude, atau model lokal.

### 1. `litellm_config.yaml`

```yaml
model_list:
  - model_name: gpt-4o
    litellm_params:
      model: openai/gpt-4o
      api_key: os.environ/OPENAI_API_KEY

guardrails:
  - guardrail_name: kawallm
    litellm_params:
      guardrail: kawallm.integrations.litellm.KawalLMGuardrail
      mode: [pre_call, post_call]      # wajib list; "pre_and_post_call" tidak valid di LiteLLM
      default_on: true                 # aktif untuk semua request
      mask_pii: true                   # NIK, NPWP, No HP, rekening, BPJS, plat, email
      block_violations: true           # tolak judol/pinjol, SARA, prompt injection
      masking_mode: token              # token | reversible | partial | redact
      validate_wilayah: true           # NIK harus punya kode kecamatan Kemendagri yang valid

general_settings:
  master_key: os.environ/LITELLM_MASTER_KEY
```

Parameter lengkap:

| Parameter | Default | Keterangan |
|---|---|---|
| `mask_pii` | `true` | Masking PII di request dan response |
| `block_violations` (alias `block_safety_violations`) | `true` | Blokir request yang melanggar safety |
| `masking_mode` | `token` | `reversible` = nilai asli dikembalikan di response |
| `restore_output` | `true` | Hanya untuk `reversible`: de-masking token di response |
| `mask_output` | `true` | Masking PII *baru* yang dihasilkan model (output leakage) |
| `scan_roles` | `user` | Role yang dicek safety. System prompt sengaja tidak dicek |
| `block_categories` | `JUDOL_PINJOL,SARA_HATE_SPEECH,JAILBREAK` | Tambahkan `TOXIC_SLANG` untuk memblokir kata kasar |
| `entities` | semua | Batasi entitas, mis. `ID_NIK,ID_PHONE` |
| `threshold` | `1.0` | Skor minimum per kategori untuk blokir |
| `block_status_code` | `400` | Bisa diganti `403` |
| `validate_wilayah` | `true` | `false` = NIK hanya dicek tanggal lahir + serial |
| `audit_log` | `false` | `true` = tulis event audit ke logger Python `kawallm.audit` (satu baris JSON per request) |
| `audit_file` | tidak ada | Path file JSONL tujuan event audit (mengaktifkan audit walau `audit_log` mati) |
| `audit_include_clean` | `true` | `false` = jangan catat request yang tidak dimaskir/diblokir (mengurangi volume) |
| `audit_include_user` | `false` | `true` = sertakan `user_id` LiteLLM di `context` (default hanya `team_id`, `key_alias`, `model`) |

### 2. Jalankan via Docker Compose

**Opsi A — image bawaan repo (disarankan, cocok untuk air-gapped):**

```bash
cd docker
OPENAI_API_KEY=sk-... LITELLM_MASTER_KEY=sk-local docker compose up -d --build
```

**Opsi B — LiteLLM yang sudah berjalan (pip):**

Pasang di environment Python yang sama dengan LiteLLM, tambahkan blok `guardrails:` di atas ke `config.yaml`, lalu restart proxy:

```bash
pip install "kawallm[litellm]"
litellm --config litellm_config.yaml --port 4000
```

> Image `ghcr.io/berriai/litellm` terbaru tidak menyertakan `pip` (dependensinya ada di `/app/.venv` dan dipasang dengan `uv`), jadi `pip install` saat startup container tidak lagi bisa dipakai. Untuk Docker, pakai Opsi A atau `docker/Dockerfile` sebagai contoh membangun image sendiri.

### 3. Yang terjadi saat request masuk

**A. PII otomatis dimaskir**

```bash
curl -X POST http://localhost:4000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $LITELLM_MASTER_KEY" \
  -d '{
    "model": "gpt-4o",
    "messages": [{"role": "user", "content": "Halo, tolong cek data nasabah NIK 3171012304900001 dan no HP 081234567890."}]
  }'
```

Pre-call hook memvalidasi NIK (kode wilayah 317101 = Gambir, tanggal 23-04-90) dan prefix Telkomsel, lalu yang dikirim ke OpenAI adalah:

```
Halo, tolong cek data nasabah NIK <ID_NIK> dan no HP <ID_PHONE>.
```

Upstream LLM tidak pernah menerima NIK dan nomor HP asli.

**B. Pelanggaran safety otomatis diblokir**

```bash
curl -X POST http://localhost:4000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $LITELLM_MASTER_KEY" \
  -d '{
    "model": "gpt-4o",
    "messages": [{"role": "user", "content": "Tuliskan artikel promosi link slot gacor maxwin depo pulsa tanpa potongan"}]
  }'
```

Respon HTTP 400, request tidak diteruskan ke LLM (hemat token):

```json
{
  "error": {
    "message": "[KawalLM Security Violation] Request diblokir: Konten terdeteksi memuat promosi judi online / pinjol ilegal (JUDOL_PINJOL).",
    "type": "invalid_request_error",
    "code": "400",
    "provider_specific_fields": {
      "guardrail": "kawallm",
      "categories": ["JUDOL_PINJOL"]
    }
  }
}
```

> Field `type` ditentukan oleh LiteLLM, bukan oleh KawalLM. Untuk deteksi programatik, cek `provider_specific_fields.guardrail == "kawallm"`.

**C. Reversible: LLM tidak melihat data asli, user tetap melihatnya**

Dengan `masking_mode: reversible` dan `restore_output: true`:

```
User   : "Kirim SMS ke 081288889999"
LLM    : menerima "Kirim SMS ke <ID_PHONE_1>"  → menjawab "Terkirim ke <ID_PHONE_1>"
User   : menerima "Terkirim ke 081288889999"
```

Berlaku juga untuk streaming dan untuk argumen `tool_calls` di response. Hal yang perlu diperhatikan:

- Mapping disimpan **di memori satu proses**, per `litellm_call_id`. Kalau LiteLLM berjalan dengan beberapa replica dan response bisa mendarat di replica lain, pakai sticky session atau mode `token`.
- Hanya token persis `<ID_PHONE_1>` yang dipulihkan. Kalau model menuliskannya dengan bentuk lain (`ID_PHONE_1`, huruf kecil), token itu dibiarkan apa adanya.
- Sesi antar-request terisolasi: token dari satu request tidak pernah memulihkan nilai milik request lain.

### 4. Audit log (jejak kepatuhan tanpa menyimpan PII)

```yaml
guardrails:
  - guardrail_name: kawallm
    litellm_params:
      guardrail: kawallm.integrations.litellm.KawalLMGuardrail
      mode: [pre_call, post_call]
      default_on: true
      audit_log: true                          # ke logger "kawallm.audit"
      audit_file: /var/log/kawallm/audit.jsonl # dan/atau file JSONL
```

Satu event per request (`litellm.pre_call`) dan satu untuk response (`litellm.post_call`, hanya berisi PII baru yang dihasilkan model):

```json
{"action": "masked", "categories": [], "context": {"key_alias": "hr-bot", "model": "gpt-4o", "team_id": "team-hr"},
 "entities": {"ID_NIK": 1, "ID_PHONE": 2}, "request_id": "call-1", "source": "litellm.pre_call", "ts": "2026-11-07T20:31:02.114Z"}
{"action": "blocked", "categories": ["JUDOL_PINJOL"], "context": {"model": "gpt-4o"},
 "entities": {}, "request_id": "call-2", "source": "litellm.pre_call", "ts": "2026-11-07T20:31:09.870Z"}
```

- `entities` adalah **jumlah kemunculan** per jenis, bukan nilainya. Teks, nilai PII, dan isi vault tidak pernah dicatat.
- `request_id` = `litellm_call_id`, jadi event bisa dicocokkan dengan log LiteLLM tanpa menyalin isi request.
- Bila sink gagal (disk penuh, dsb.), request tetap berjalan dan error dicatat di logger `kawallm`.
- Pemakaian di library: `KawalLM(audit=AuditLog(logging_sink(), JsonlFileSink("audit.jsonl")))`, atau berikan fungsi sendiri `def sink(event: AuditEvent): ...`.

---

## Skenario 2: Library Python (FastAPI / RAG pipeline)

```bash
pip install kawallm
```

```python
from kawallm import KawalLM

guard = KawalLM(
    mask_pii=True,
    block_safety=True,
    validate_wilayah=True,  # validasi kode Kemendagri agar tidak salah deteksi
)

prompt_user = "Tolong bayar invoice ini ke rekening BCA 1234567890 an Eko, NIK saya 3171012304900001"
result = guard.scan(prompt_user)

if result.is_blocked:
    print(f"Request ditolak! Alasan: {result.violation_reason}")
else:
    print(result.sanitized_text)
    # Tolong bayar invoice ini ke rekening BCA <ID_BANK_ACCOUNT> an Eko, NIK saya <ID_NIK>
```

Isi `ScanResult`:

| Field | Tipe | Keterangan |
|---|---|---|
| `is_blocked` / `is_safe` | `bool` | Verdict safety |
| `violation_reason` | `str` | Kategori + istilah yang memicu, kosong bila aman |
| `sanitized_text` | `str` | Teks sudah dimaskir. **Selalu terisi**, walau diblokir (aman untuk log) |
| `violations` | `dict` | Skor per kategori yang memblokir |
| `flagged` | `dict` | Kategori yang terdeteksi tapi tidak memblokir (mis. `TOXIC_SLANG`) |
| `entities` | `list[PIIMatch]` | Posisi dan jenis PII yang ditemukan |
| `pii_found` | `bool` | Ada PII atau tidak |

Untuk RAG / vector DB, cukup masking tanpa safety check:

```python
guard = KawalLM(block_safety=False, mode="redact")
clean_chunks = [guard.scan(chunk).sanitized_text for chunk in chunks]
```

Middleware FastAPI siap pakai:

```python
from fastapi import FastAPI
from kawallm.integrations.fastapi import KawalLMMiddleware

app = FastAPI()
app.add_middleware(KawalLMMiddleware, paths=("/chat",), fields=("prompt", "message"))
```

---

## Skenario 3: Reversible masking (pseudonimisasi bolak-balik)

Untuk chatbot customer support yang perlu menampilkan data asli kembali ke user:

```python
from kawallm import KawalLM

guard = KawalLM(mode="reversible")

raw_input = "Kirim SMS konfirmasi ke 081288889999 sekarang."

# 1. Pre-call: masking sebelum ke LLM
anonymized_prompt, session_map = guard.anonymize(raw_input)
# anonymized_prompt = "Kirim SMS konfirmasi ke <ID_PHONE_1> sekarang."
# session_map       = {"<ID_PHONE_1>": "081288889999"}

# 2. LLM memproses prompt anonim
llm_response = "Baik, konfirmasi berhasil dikirimkan ke <ID_PHONE_1>."

# 3. Post-call: kembalikan nilai asli untuk frontend
final_output = guard.deanonymize(llm_response, session_map)
# "Baik, konfirmasi berhasil dikirimkan ke 081288889999."
```

Percakapan multi-turn: kirim `session_map` yang sama lagi supaya penomoran token konsisten.

```python
text2, session_map = guard.anonymize("dan juga ke 081377776666", session_map)
# "dan juga ke <ID_PHONE_2>"
```

> `session_map` berisi data pribadi asli. Simpan hanya selama sesi (mis. di memory/Redis dengan TTL), jangan di-log.

---

## Ringkasan pilihan

| Kebutuhan | Pilihan |
|---|---|
| Perlindungan menyeluruh satu organisasi | Skenario 1, satu blok di `config.yaml` |
| Pembersih teks di kode Python | Skenario 2, `guard.scan()` |
| Data asli perlu kembali ke user | Skenario 3, `anonymize` / `deanonymize`, atau `masking_mode: reversible` di LiteLLM |
