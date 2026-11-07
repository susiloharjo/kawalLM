# Changelog

Format mengikuti [Keep a Changelog](https://keepachangelog.com/); versi mengikuti [SemVer](https://semver.org/).

## [Unreleased]

### Added
- LiteLLM `pre_call`: PII di argumen `tool_calls` / `function_call` pada request kini dimaskir (JSON tetap valid, angka telanjang menjadi string token). Safety scan atas argumen mengikuti `scan_roles`.

### Fixed
- False positive: setiap kalimat berisi kata "slot" (mis. "slot waktu") diblokir, karena istilah `slot777` di kamus dinormalisasi menjadi `slot` berbobot 1.0. Istilah itu dihapus; test baru memastikan tidak ada istilah kamus yang berubah oleh `normalize()`.
- "gacor" sendirian (istilah slang umum) kini berbobot 0.5, sehingga tidak lagi memblokir sendiri; tetap memblokir bersama sinyal judol lain.

### Added (tests)
- `tests/data/benign_id.txt` + `tests/test_benign.py`: eval set false positive (kalimat Indonesia wajar), target < 1%.

### Changed
- Versi paket sekarang satu sumber (`src/kawallm/__init__.py`).
- Paket menyertakan `py.typed` (PEP 561).
- Workflow publish menjalankan test dan memastikan tag sama dengan versi sebelum rilis.

## [0.1.0]

- Rilis awal: masking PII Indonesia (NIK, NPWP, HP, rekening, BPJS, plat, email), safety scanner (judol/pinjol, SARA, jailbreak), integrasi LiteLLM, Presidio, FastAPI.
