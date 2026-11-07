"""Latency / throughput / memory benchmark for the NFR table.

    python benchmarks/bench_latency.py --words 1000 --iterations 2000

Measures one full guard pass (safety scan + PII mask) per payload on a
single core. Payloads are synthetic: ordinary Indonesian business text with
~1 PII value per 50 words.
"""

from __future__ import annotations

import argparse
import json
import platform
import random
import resource
import statistics
import time

from kawallm import KawalLMEngine, synthetic

FILLER = (
    "mohon bantu ringkas laporan rapat koordinasi proyek infrastruktur jaringan data center minggu ini "
    "tim sudah menyelesaikan instalasi perangkat dan uji fungsi berjalan baik namun masih ada kendala "
    "pada jadwal pengiriman material dari vendor sehingga perlu eskalasi ke manajemen untuk keputusan "
    "anggaran tambahan serta penyesuaian timeline pekerjaan tahap berikutnya di lokasi pelanggan"
).split()


def payload(words: int, seed: int) -> str:
    r = random.Random(seed)
    out = []
    for i in range(words):
        if i % 50 == 25:
            kind = r.choice(["nik", "phone", "npwp", "bank"])
            out.append(
                {
                    "nik": f"NIK {synthetic.nik(seed + i)}",
                    "phone": f"HP {synthetic.phone(seed + i)}",
                    "npwp": f"NPWP {synthetic.npwp(seed + i)}",
                    "bank": f"BCA {synthetic.digits(10, seed + i)}",
                }[kind]
            )
        else:
            out.append(r.choice(FILLER))
    return " ".join(out)


def pct(xs: list[float], p: float) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--words", type=int, default=1000)
    ap.add_argument("--iterations", type=int, default=2000)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    eng = KawalLMEngine()
    payloads = [payload(a.words, s) for s in range(50)]
    for p in payloads[:5]:  # warm-up
        eng.check_safety(p)
        eng.mask_pii(p)

    lat = []
    t_all = time.perf_counter()
    for i in range(a.iterations):
        p = payloads[i % len(payloads)]
        t0 = time.perf_counter()
        eng.check_safety(p)
        eng.mask_pii(p)
        lat.append((time.perf_counter() - t0) * 1000)
    total = time.perf_counter() - t_all

    rss_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    res = {
        "python": platform.python_version(),
        "cpu": platform.processor() or platform.machine(),
        "words_per_payload": a.words,
        "iterations": a.iterations,
        "p50_ms": round(statistics.median(lat), 3),
        "p95_ms": round(pct(lat, 95), 3),
        "p99_ms": round(pct(lat, 99), 3),
        "throughput_rps_single_core": round(a.iterations / total, 1),
        "peak_rss_mb": round(rss_mb, 1),
    }
    if a.json:
        print(json.dumps(res, indent=2))
    else:
        for k, v in res.items():
            print(f"{k:28s} {v}")


if __name__ == "__main__":
    main()
