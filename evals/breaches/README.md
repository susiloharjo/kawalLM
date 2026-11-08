# Eval kebocoran KawalLM

Suite offline untuk pola kegagalan yang berulang dalam review. Semua identifier sintetis: NIK, telepon, dan BPJS dibuat dengan seed tetap melalui `kawallm.synthetic`; alamat, paspor, plat, koordinat, dan percakapan adalah contoh buatan. Tidak perlu API key, model eksternal, atau data pengguna.

## Menjalankan

Dari root repo, gunakan environment yang sudah ada. Jika dependency belum tersedia:

```bash
uv pip install --python .venv/bin/python -e ".[dev,litellm]"
```

Jalankan eval beserta laporan JUnit ke luar repo:

```bash
.venv/bin/python -B -m pytest evals/breaches -vv -p no:cacheprovider --junitxml=/tmp/kawallm-breach-eval.xml
```

Lanjutkan dengan suite regresi proyek:

```bash
.venv/bin/python -B -m pytest -p no:cacheprovider
```

`evals/` sengaja di luar `testpaths` default. Dependency integrasi diimpor langsung: dependency hilang menyebabkan error, bukan skip yang tampak hijau. Lulus hanya jika semua kasus **PASS**, exit code 0, dan tidak ada skipped/xfail/xpass/error. Laporan hanya memuat data sintetis. Tidak perlu menjalankan atau menghubungi Claude lewat API; Claude Code cukup mengeksekusi perintah di atas.

## Cakupan dan ekspektasi

| ID keluarga | Skenario | Ekspektasi |
|---|---|---|
| SAFE / BENIGN | Injection eksplisit, judol, obfuscation, kontrol edukatif | Serangan diblokir; kontrol tetap lolos |
| PII-001 | NIK biasa, zero-width, bidi, fullwidth | Seluruh nilai termaskir |
| HTTP-001 | JSON, vendor `+json`, variasi kapitalisasi | Perilaku safety/masking sama |
| HTTP-002 | Field role system dari pemanggil | Tidak mengecualikan prompt biasa |
| HTTP-003 | Lone surrogate di field lain | Sanitasi tetap berlaku; audit sesuai hasil |
| PARTS-001 | Satu NIK terbelah / dua NIK utuh bersebelahan | Tidak kehilangan deteksi atau bagian teks |
| STREAM-001 | Chunk 1/7/63/64/65/257 karakter | Output tepat; lengkap sebelum finish_reason |
| TOOL-001 | Streaming tool_calls dan function_call lama | PII termaskir dan argumen JSON lengkap/valid |
| TOOL-002 | Pemulihan newline dan PII baru dari model | Hanya data pemanggil dipulihkan; JSON valid |
| SESSION-001 | Dua API key, call ID sama, metadata sesi disuplai | Tidak dapat memulihkan data pengguna lain |
| RESTORE-001 | Koordinat tanpa placeholder lain | Round-trip utuh, termasuk streaming |
| ADDR | Nomor rumah/RT/RW/blok setelah kelurahan | Generalisasi hanya menyisakan wilayah |
| CONFIG-001 | Alias ID_BPJS dengan redact | Berlaku untuk KES dan TK; tidak reversible |

Ekspektasi pada JSON diperiksa setelah parsing, sehingga kegagalan escape tidak tertutupi oleh pencarian substring saja. Streaming diperiksa pada saat `finish_reason`, bukan hanya setelah seluruh chunk dikumpulkan. Kontrol benign mencegah solusi semu berupa memblokir semua request.

## Prompt siap pakai untuk Claude Code

```text
Jalankan evals/breaches sesuai README-nya lalu suite pytest default.
Tugas kali ini evaluasi saja: jangan mengedit source, test, expected result, atau dependency manifest.
Jangan menggunakan data pribadi asli, API model, atau layanan eksternal untuk reproduksi.
Jika dependency belum ada, laporkan terlebih dahulu; jangan menganggap skip sebagai lulus.
Laporkan commit, git status awal/akhir, versi Python dan dependency integrasi,
perintah, exit code, jumlah pass/fail/skip/error, serta lokasi laporan JUnit.
Untuk setiap kegagalan: tuliskan node ID pytest, input sintetis minimal, expected,
actual, dampak, dan lokasi kode yang diduga menyebabkan masalah.
Jangan mengubah ekspektasi agar hijau. Jika ekspektasi dianggap salah, jelaskan
alasannya terpisah dan tetap laporkan hasil asli. Jangan menyimpulkan aplikasi
bebas kebocoran hanya karena seluruh eval lulus.
```

## Batas evaluasi dan perluasan

Ini pengujian deterministik lokal: FastAPI melalui TestClient dan LiteLLM melalui hook dengan objek respons tiruan. Belum menguji transport SSE pada proxy sungguhan, logging/cache provider, autentikasi deployment, multi-replica, atau serangan semantik tanpa pola yang didukung. Jangan menghitung seluruh variasi chunk sebagai serangan independen atau menyebut tingkat lolos ini sebagai metrik keamanan dunia nyata.

Tambahkan payload safety/alamat di `cases.json` dengan ID baru dan expected eksplisit. Untuk jalur baru, tambahkan test dengan input, ekspektasi, dan kontrol negatif yang relevan. Pertahankan ID lama, gunakan seed tetap, dan sertakan kasus gagal sebagai regresi setelah perbaikannya disetujui.
