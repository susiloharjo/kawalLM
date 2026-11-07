## Ringkasan

<!-- Apa yang berubah dan kenapa -->

## Jenis perubahan

- [ ] Kamus (kata/frasa baru di `safety/words/`)
- [ ] Detektor / validator PII
- [ ] Rule jailbreak / SARA
- [ ] Integrasi (LiteLLM / Presidio / FastAPI)
- [ ] Dokumentasi / CI / lainnya

## Checklist

- [ ] `uv run pytest` hijau dan coverage tetap ≥ 90%
- [ ] `uvx ruff check . && uvx ruff format --check .` bersih
- [ ] Test baru memakai **data sintetis** (`kawallm.synthetic`), tidak ada data pribadi asli
- [ ] Untuk kamus: tiap istilah sudah dipertimbangkan potensi false positive-nya (bobot 0.3/0.5 untuk kata ambigu)
- [ ] Benchmark tidak memburuk signifikan (`python benchmarks/bench_latency.py`) bila menyentuh hot path
- [ ] `README.md` diperbarui bila perilaku, entitas, parameter, atau keterbatasan berubah, dan `CHANGELOG.md` (bagian Unreleased) diisi
- [ ] Data pihak ketiga yang ditambahkan berlisensi kompatibel Apache-2.0 dan dicatat di `NOTICE`
