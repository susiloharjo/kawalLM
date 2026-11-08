# Changelog

Format mengikuti [Keep a Changelog](https://keepachangelog.com/); versi mengikuti [SemVer](https://semver.org/).

## [Unreleased]

### Fixed
- Streaming: teks yang menahan buffer kini 160 karakter (sebelumnya 64), sehingga keyword rekening yang muncul sampai 110 karakter sesudah nomor tetap terlihat detektor. Nomor rekening tidak lagi bocor pada chunk kecil.
- `thinking_blocks` pada stream ikut dimaskir: teks ditahan per block (per `index`) dan dikeluarkan bersama signature-nya, sudah dimaskir. Dua block dengan angka yang sama tidak lagi digabung, dan thinking tidak lagi hilang saat dirakit ulang oleh LiteLLM. Block bertanda tangan yang teksnya berubah karena masking (atau restore) tidak dikirim dengan signature asli: di stream signature dikosongkan, di respons lengkap block dibuang.
- Request: `reasoning_content` dan `thinking_blocks` di riwayat assistant (serta blok `thinking` di `content`) dimaskir sebelum dikirim ke provider. Blok thinking yang bertanda tangan dan berisi PII dibuang, karena mengubah teksnya akan ditolak provider.
- Angka dengan eksponen lebih dari ±4096 di argumen tool-call ditolak (400) tanpa diekspansi; sebelumnya `1e100000` menghasilkan string 100 001 karakter.
- Angka di argumen tool-call dikeluarkan dari teks aslinya: `1e400` tetap `1e400` (sebelumnya `Infinity`, JSON tidak valid), dan presisi desimal panjang tidak hilang.
- `NaN`/`Infinity` di argumen tool-call tidak lagi diubah menjadi JSON tidak valid; argumen itu diperlakukan sebagai teks biasa.
- Angka valid yang diikuti angka lain ("HP 081234567890 25 November", "rekening BCA 1234567890 1000000") kini tetap dimaskir: detektor HP, telepon rumah, dan rekening mencoba kandidat utuh lalu bagian-bagiannya (terpanjang dulu).
- Streaming kini identik dengan non-streaming untuk setiap pemotongan chunk; konteks sebelum/sesudah dipakai saat mendeteksi di buffer hold-back.
- `reasoning_content`, `refusal`, dan `thinking_blocks` ikut dimaskir (stream dan respons lengkap), masing-masing dengan buffer sendiri.
- Argumen tool-call: kunci JSON ikut dimaskir (tabrakan kunci diberi akhiran `#`), float seperti `3171011501900001.0` atau `3.17e15` dikenali, dan hasilnya selalu JSON valid.
- Email dimaskir utuh walau digit di dalamnya mirip entitas lain (`EMAIL` kini prioritas tertinggi).
- Audit: `context["path"]` FastAPI dimaskir.
- Vault: sesi kedaluwarsa dihapus saat dibaca, ada `Vault.sweep()`, dan penomoran token reversible O(1) per entitas (sebelumnya kuadratik).
- CLI: `--entities` (profil atau daftar) dan `--mode generalize`; Presidio: parameter `profile`.
- docker-compose: `LITELLM_MASTER_KEY` wajib diisi (tanpa default); rilis menjalankan `evals/breaches`.

## [0.3.0] - 2026-11-09

**Perhatian keamanan:** 0.2.2 dan 0.2.3 punya celah di middleware FastAPI (lihat *Fixed* di bawah). Pengguna `KawalLMMiddleware` sebaiknya segera meningkatkan ke 0.3.0.

### Added
- Profil `extended` (opt-in, `entities="extended"`): quasi-identifier `ID_BIRTHDATE`, `ID_AGE`, `ID_POSTAL_CODE`, `ID_ADDRESS`, `GEO_COORDINATES`. Setiap entitas membutuhkan label atau penanda struktural untuk menjaga false positive tetap rendah. Perilaku default tidak berubah.
- Mode masking `generalize`: menurunkan presisi (tanggal lahir menjadi tahun, usia menjadi rentang, kode pos 3 digit, alamat menjadi wilayahnya, koordinat dibulatkan). Entitas tanpa generalisasi menjadi token biasa.
- `entities=` menerima nama profil (`core`, `extended`) atau daftar dipisah koma; `kawallm.pii.expand_entities`, `PROFILES`, `QUASI_ENTITIES`.
- `mode_by_entity`: mode masking berbeda per entitas (mis. HP dan email reversible, NIK token). Di `KawalLMEngine`/`KawalLM`, guardrail LiteLLM (`mode_by_entity`, dict atau string `ID_PHONE=reversible,EMAIL=redact`), dan middleware FastAPI. Mode eksplisit pada satu panggilan mengalahkan pemetaan. Nama entitas dan mode divalidasi saat konstruksi; `reversible_enabled` dan `mode_for()` tersedia di engine.
- Audit log: field `flags` dengan `combined_quasi_identifiers` bila satu request memuat dua atau lebih jenis quasi-identifier. Hanya jumlah, tanpa nilai.

### Fixed
- **Keamanan**: middleware FastAPI gagal terbuka bila hasil sanitasi tidak bisa di-encode UTF-8 (mis. surrogate tunggal `\ud800` di body JSON): body asli, termasuk data yang seharusnya dimaskir, diteruskan ke handler. Penyebabnya `except ValueError` yang terlalu luas (ada sejak 0.2.2). Sekarang hanya kegagalan parse yang meneruskan body asli; kegagalan sanitasi atau encoding menolak request (400), surrogate ditulis sebagai escape JSON, dan JSON yang terlalu dalam ditolak.
- Placeholder reversible `GEO_COORDINATES` yang berdiri sendiri kini dipulihkan (`unmask` dan streaming); pra-filter hanya mengenali `id|email|ip`.
- `generalize` untuk alamat hanya menyimpan komponen administratif (kelurahan, kecamatan, kota); nomor rumah, RT/RW, dan blok tidak lagi ikut.
- `mode_by_entity={"ID_BPJS": ...}` kini berlaku untuk `ID_BPJS_KES` dan `ID_BPJS_TK`; sebelumnya diterima tetapi diabaikan.
- Middleware FastAPI: dua nilai lengkap di text part yang berdekatan (mis. dua NIK) kini keduanya termask; sebelumnya penggabungan membuat keduanya menjadi satu rangkaian digit panjang yang tidak cocok.

## [0.2.3] - 2026-11-08

### Added
- Hasil guardrail LiteLLM kini ditulis ke `standard_logging_guardrail_information` (`guardrail_provider="kawallm"`, status `success` atau `guardrail_intervened`, jumlah entitas per jenis). Dashboard dan logger LiteLLM sekarang bisa menampilkan evaluasi dan request yang diblokir. Hanya jumlah dan nama kategori yang dicatat, tanpa teks atau nilai PII. Versi LiteLLM tanpa helper ini dilewati, dan kegagalan pencatatan tidak menggagalkan request.

## [0.2.2] - 2026-11-08

### Fixed
- FastAPI middleware: `role` di level yang sama dengan field lain tidak lagi membebaskan field itu dari safety scan. Pengecualian system message hanya berlaku untuk `content` pesan itu sendiri.
- FastAPI middleware: body dengan `Content-Type: application/vnd.api+json` (dan media type `+json` lain) kini diperiksa. Sebelumnya dilewati karena pencocokan substring. Body tanpa Content-Type juga diperiksa. Form dan multipart tidak diperiksa.
- Streaming LiteLLM: teks yang masih tertahan dilepas di chunk yang membawa `finish_reason`, sebelum tanda selesai dikirim.
- Argumen tool-call: nilai yang dipulihkan (mis. nomor dengan newline) di-escape sebagai string JSON, sehingga argumen tetap JSON valid.
- Dua entitas lengkap di bagian text yang berdekatan kini keduanya termask (regresi dari penggabungan bagian).

## [0.2.1] - 2026-11-08

### Added
- Dukungan paspor RI seri 2 huruf (`[A-Z]{1,2}\s?\d{7}`, mis. `AA 1234567`, `XD1234567`) pada `ID_PASSPORT`.
- Penambahan spesifikasi rekening bank populer pada `ID_BANK_ACCOUNT`: `blu` / `bca digital` (12 digit), `muamalat` (10 digit), `bjb` (13 digit), `bank dki` (11–12 digit), dan `bank jatim` (10 digit).
- Parameter `scan_system_messages: bool = False` pada `KawalLMMiddleware` (FastAPI) agar `role: "system"` dilewati secara default, serta deteksi prompt injection yang dipecah lintas elemen `content` multimodal.

### Changed
- Optimasi latensi `detect_pii()` dan `normalize()`: pre-filter digit/`@`, deduplikasi `text.lower()` dengan cache Aho-Corasick pada `mentions_any()`, serta pre-filter Aho-Corasick untuk karakter berulang (`_REPEAT_AUTOMATON`), menurunkan latensi `p95` 1.000 kata dari sekitar 4,8 ms ke sekitar 1,9 ms di mesin pengembangan (Xeon Silver 4416+), dan teks tanpa angka ke `< 1 µs`.
- Penguatan normalisasi anti-evasion: dukungan spaced-out separator campuran (`s.l-o_t`), translasi homoglyph Cyrillic/Greek, pemisahan suffix angka ekor (`g4c0r88`, `m4xw1n77`), dan stripping karakter Unicode bidirectional formatting WhatsApp (`\u202a-\u202e`, `\u2066-\u2069`).
- Publish kembali memakai attestation PEP 740 (provenance). `0.2.0` terbit tanpa provenance karena layanan Rekor sedang error saat rilis.

### Fixed
- Streaming LiteLLM: menahan pemotongan buffer yang membelah span entitas multi-token (`ID_PLATE`, `ID_PASSPORT`).
- Penerimaan nama sub-entitas `ID_BPJS_KES` dan `ID_BPJS_TK` pada parameter `entities`.
- Sesi reversible diikat ke pemanggil: ID sesi di sisi request berasal dari `litellm_call_id` (dibuat server) dan kunci vault diberi awalan hash identitas pemanggil (API key, team, user). ID sesi yang dikirim client di `metadata` diabaikan.
- Nilai yang terpecah di beberapa text part satu pesan (mis. `NIK 31710115` + `01900001`) kini termask.
- Streaming: field `function_call` (format lama) ikut ditahan dan dimask seperti `tool_calls`; nama fungsi hanya dikirim sekali.
- Streaming: potongan buffer tidak lagi membelah entitas (paspor `A 1234567`, plat `B 1234 ABC`).
- Homoglyph Cyrillic/Yunani tambahan (`и`, `һ`, `ԁ`, `ԝ`, `ɡ`, `ո`) dinormalisasi; digit fullwidth dan karakter compat lain difold ke NFKC sebelum deteksi PII, dengan posisi tetap mengacu ke teks asli.
- Argumen tool-call di atas 256.000 karakter atau JSON lebih dalam dari 64 level ditolak dengan HTTP 400 (sebelumnya `RecursionError` atau pemrosesan yang lambat).
- Streaming dengan token `@` yang sangat panjang lebih cepat: penahanan kandidat email dibatasi 512 karakter (RFC 5321 membatasi email 254 karakter).
- `mask_pii=False` tidak lagi memask nilai yang terpecah di beberapa text part.

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
