# Changelog

Format mengikuti [Keep a Changelog](https://keepachangelog.com/); versi mengikuti [SemVer](https://semver.org/).

## [0.2.0] - 2026-11-07

Lingkup rilis ini: deteksi PII Indonesia dan pola safety yang eksplisit. Bukan guardrail umum (tidak ada classifier semantik); lihat *Keterbatasan* di README.

### Changed (breaking, mode reversible)
- Placeholder reversible sekarang memuat nonce acak per sesi: `<ID_NIK_1>` menjadi `<ID_NIK_1_a3f2c9>`. Mode `token`/`redact`/`partial` tidak berubah. Peta sesi lama (0.1.x) tetap bisa dipulihkan lewat pencocokan persis, tetapi token baru selalu bernonce. Alasan: teks yang diketik user atau peta sesi yang salah dulu bisa memulihkan data asli tanpa error.
- Pemulihan placeholder kini toleran terhadap tulisan ulang LLM (huruf kecil, tanpa kurung, spasi, `[..]`, `(..)`, `&lt;..&gt;`). Hanya placeholder yang ada di peta sesi yang dipulihkan.
- Hold-back streaming LiteLLM 48 -> 64 karakter.

### Added
- `IP_ADDRESS`: alamat IPv4 dan IPv6 dimaskir, divalidasi dengan `ipaddress` (octet > 255, nol di depan, nomor build, `v1.2.3.4`, MAC, jam, dan `Foo::Bar` tidak ikut). Aktif secara default, termasuk IP internal; matikan lewat `entities`. Placeholder reversible: `<IP_ADDRESS_1_a3f2c9>`.
- Telepon rumah (`ID_PHONE`, `meta["landline"]`): `(021) 5551234`, `021-5551234`, `+62 21 5551234`; angka tanpa pemisah hanya dengan kata kunci (`telp`, `fax`, ...). Kode area divalidasi terhadap daftar kota besar/ibu kota kabupaten (`AREA_CODES`), tanggal, versi, dan IP tidak ikut terdeteksi.
- `StreamDeanonymizer` (+ `KawalLM.deanonymize_stream`, `KawalLMEngine.unmask_stream`): pemulihan placeholder untuk respons streaming di luar LiteLLM.
- Protokol `VaultBackend` (`KawalLMEngine(..., vault=...)`) untuk session store kustom (mis. Redis) serta eviksi sesi `Vault` in-memory `O(1)` amortized berbasis urutan kedaluwarsa.
- Dukungan `audit=` di `KawalLMMiddleware` (FastAPI), `EMAIL` & `validate_wilayah` di `KawalLMRecognizer` (Presidio), serta de-masking `delta.tool_calls` pada streaming LiteLLM.
- Audit log (`kawallm.audit`): `AuditLog`, `AuditEvent`, `logging_sink`, `JsonlFileSink`. Event berisi aksi, jumlah kemunculan per entitas, dan kategori pelanggaran, tanpa nilai PII, teks, atau isi vault. `KawalLM(audit=...)` + `scan(..., context=...)`; guardrail LiteLLM: `audit_log`, `audit_file`, `audit_include_clean`, `audit_include_user`. Sink yang gagal tidak menggagalkan request.
- Detektor identitas baru: `ID_NIP` (18 digit, divalidasi tanggal lahir, bulan pengangkatan, gender), `ID_NISN`, `ID_PASSPORT`, `ID_SIM` (ketiganya wajib kata kunci di dekat nomor). Termasuk generator `kawallm.synthetic.nip/nisn/passport/sim` dan dukungan Presidio.

### Fixed
- Streaming LiteLLM: e-mail di aliran panjang tanpa spasi tidak lagi terpotong di batas potongan (token berisi `@` ditahan sampai selesai, dengan batas aman).
- Tool-call output dari model kini dimaskir (termasuk streaming); `restore_output=False` tidak lagi memulihkan argumen tool.
- Streaming LiteLLM: holdback dan konteks per pilihan (`n > 1`), chunk penutup berisi `choices=[]` tidak menghilangkan teks tertahan, dan konteks kata kunci (mis. `rekening`) lintas potongan tetap berlaku.
- Field JSON dipakai sebagai konteks deteksi (`{"rekening": "1234567890"}` termask); injeksi yang dipecah di beberapa text part pada satu pesan kini diperiksa gabungan.
- Normalisasi: pemisah berbeda antarkata tidak lagi menggabungkan kata (`s.l.o.t g.4.c.0.r` -> `slot gacor`).
- Jailbreak urutan kata Inggris (`ignore previous instructions`) kini terblokir.
- Karakter zero-width di dalam nomor (`0812\u200b34567890`) tidak lagi lolos dari masking PII.
- Frasa ambigu `langsung cair` dan `link alternatif` tidak lagi memblokir sendiri; kalimat edukasi kini mendapat bobot separuh untuk istilah ambigu.
- Vault: sesi yang sudah kedaluwarsa tidak lagi menghidupkan mapping lama saat dipakai ulang.
- Penyelesaian overlap PII kini O(n log n) (sebelumnya kuadratik).
- Evasion menggunakan karakter *zero-width* (`\u200b`, `\u200c`, `\u200d`, `\ufeff`, `\u00ad`) kini dihapus saat normalisasi safety.
- Detektor rekening bank tidak lagi mencocokkan angka yang mencampur separator berbeda (mis. tanggal dan jam `2026-11-07 20.45` di dekat kata `transfer`).
- Buffer streaming LiteLLM kini memiliki batas fallback aman untuk teks panjang tanpa spasi (URL panjang, base64, JSON rapat).

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
