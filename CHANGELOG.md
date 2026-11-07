# Changelog

Format mengikuti [Keep a Changelog](https://keepachangelog.com/); versi mengikuti [SemVer](https://semver.org/).

## [Unreleased]

### Changed (breaking, mode reversible)
- Placeholder reversible sekarang memuat nonce acak per sesi: `<ID_NIK_1>` menjadi `<ID_NIK_1_a3f2c9>`. Mode `token`/`redact`/`partial` tidak berubah. Peta sesi lama (0.1.x) tetap bisa dipulihkan lewat pencocokan persis, tetapi token baru selalu bernonce. Alasan: teks yang diketik user atau peta sesi yang salah dulu bisa memulihkan data asli tanpa error.
- Pemulihan placeholder kini toleran terhadap tulisan ulang LLM (huruf kecil, tanpa kurung, spasi, `[..]`, `(..)`, `&lt;..&gt;`). Hanya placeholder yang ada di peta sesi yang dipulihkan.
- Hold-back streaming LiteLLM 48 -> 64 karakter.

### Added
- `IP_ADDRESS`: alamat IPv4 dan IPv6 dimaskir, divalidasi dengan `ipaddress` (octet > 255, nol di depan, nomor build, `v1.2.3.4`, MAC, jam, dan `Foo::Bar` tidak ikut). Aktif secara default, termasuk IP internal; matikan lewat `entities`. Placeholder reversible: `<IP_ADDRESS_1_a3f2c9>`.
- Telepon rumah (`ID_PHONE`, `meta["landline"]`): `(021) 5551234`, `021-5551234`, `+62 21 5551234`; angka tanpa pemisah hanya dengan kata kunci (`telp`, `fax`, ...). Kode area divalidasi terhadap daftar kota besar/ibu kota kabupaten (`AREA_CODES`), tanggal, versi, dan IP tidak ikut terdeteksi.
- `StreamDeanonymizer` (+ `KawalLM.deanonymize_stream`, `KawalLMEngine.unmask_stream`): pemulihan placeholder untuk respons streaming di luar LiteLLM.

### Added
- Audit log (`kawallm.audit`): `AuditLog`, `AuditEvent`, `logging_sink`, `JsonlFileSink`. Event berisi aksi, jumlah kemunculan per entitas, dan kategori pelanggaran, tanpa nilai PII, teks, atau isi vault. `KawalLM(audit=...)` + `scan(..., context=...)`; guardrail LiteLLM: `audit_log`, `audit_file`, `audit_include_clean`, `audit_include_user`. Sink yang gagal tidak menggagalkan request.

### Added
- Detektor identitas baru: `ID_NIP` (18 digit, divalidasi tanggal lahir, bulan pengangkatan, gender), `ID_NISN`, `ID_PASSPORT`, `ID_SIM` (ketiganya wajib kata kunci di dekat nomor). Termasuk generator `kawallm.synthetic.nip/nisn/passport/sim` dan dukungan Presidio.

## [0.1.1] - 2026-11-07

### Added
- LiteLLM `pre_call`: PII di argumen `tool_calls` / `function_call` pada request kini dimaskir (JSON tetap valid, angka telanjang menjadi string token). Safety scan atas argumen mengikuti `scan_roles`.

### Fixed
- False positive: setiap kalimat berisi kata "slot" (mis. "slot waktu") diblokir, karena istilah `slot777` di kamus dinormalisasi menjadi `slot` berbobot 1.0. Istilah itu dihapus; test baru memastikan tidak ada istilah kamus yang berubah oleh `normalize()`.
- "gacor" sendirian (istilah slang umum) kini berbobot 0.5, sehingga tidak lagi memblokir sendiri; tetap memblokir bersama sinyal judol lain.

### Tests
- `tests/data/benign_id.txt` + `tests/test_benign.py`: eval set false positive (kalimat Indonesia wajar), target < 1%.

### Changed
- Versi paket sekarang satu sumber (`src/kawallm/__init__.py`).
- Paket menyertakan `py.typed` (PEP 561).
- Workflow publish menjalankan test dan memastikan tag sama dengan versi sebelum rilis.

## [0.1.0]

- Rilis awal: masking PII Indonesia (NIK, NPWP, HP, rekening, BPJS, plat, email), safety scanner (judol/pinjol, SARA, jailbreak), integrasi LiteLLM, Presidio, FastAPI.
