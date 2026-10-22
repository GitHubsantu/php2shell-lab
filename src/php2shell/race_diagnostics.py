"""Module D - harmless concurrency diagnostics.

Measures latency distribution, error rate, timeouts and worker churn. No memory
corruption model, no shell.
"""
from __future__ import annotations

import statistics
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

import requests

from .config import AppConfig
from .target_validation import validate_target


@dataclass
class RaceReport:
    url: str
    concurrency: int
    per_worker: int
    total: int = 0
    ok: int = 0
    errors: int = 0
    timeouts: int = 0
    status_codes: Counter = field(default_factory=Counter)
    latencies: list[float] = field(default_factory=list)
    worker_ids: Counter = field(default_factory=Counter)
    wall_seconds: float = 0.0
    notes: list[str] = field(default_factory=list)

    def percentile(self, p: float) -> float | None:
        if not self.latencies:
            return None
        ordered = sorted(self.latencies)
        idx = min(len(ordered) - 1, int(round((p / 100.0) * (len(ordered) - 1))))
        return round(ordered[idx], 2)

    def as_dict(self) -> dict:
        return {
            "url": self.url,
            "concurrency": self.concurrency,
            "per_worker": self.per_worker,
            "total": self.total,
            "ok": self.ok,
            "errors": self.errors,
            "timeouts": self.timeouts,
            "error_rate_pct": round(100.0 * self.errors / self.total, 2) if self.total else None,
            "status_codes": dict(self.status_codes),
            "latency_ms": {
                "min": self.percentile(0),
                "p50": self.percentile(50),
                "p90": self.percentile(90),
                "p99": self.percentile(99),
                "max": round(max(self.latencies), 2) if self.latencies else None,
                "mean": round(statistics.fmean(self.latencies), 2) if self.latencies else None,
            },
            "distinct_workers": len(self.worker_ids),
            "worker_hits": dict(self.worker_ids),
            "wall_seconds": round(self.wall_seconds, 3),
            "requests_per_second": round(self.total / self.wall_seconds, 2) if self.wall_seconds else None,
            "notes": self.notes,
        }


def _one(url: str, cfg: AppConfig, timeout: float, headers: dict) -> tuple:
    started = time.perf_counter()
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=False, headers=headers)
        elapsed = (time.perf_counter() - started) * 1000.0
        worker = resp.headers.get("X-P2S-Worker") or resp.headers.get("X-P2S-Pid")
        return resp.status_code, elapsed, worker, None
    except requests.Timeout:
        return None, (time.perf_counter() - started) * 1000.0, None, "timeout"
    except requests.RequestException as exc:
        return None, (time.perf_counter() - started) * 1000.0, None, str(exc)


def run_race(target: str, cfg: AppConfig, concurrency: int | None = None,
             per_worker: int | None = None) -> RaceReport:
    rcfg = cfg.data["race"]
    concurrency = int(concurrency or rcfg["concurrency"])
    per_worker = int(per_worker or rcfg["requests_per_worker"])
    timeout = float(rcfg["timeout"])

    validation = validate_target(target, cfg)
    report = RaceReport(url=target, concurrency=concurrency, per_worker=per_worker)
    if not validation.allowed:
        report.notes.append(f"target rejected: {validation.reason}")
        return report

    headers = {
        "User-Agent": "php2shell-lab/0.1 (race)",
        str(cfg.data["probe"]["token_header"]): str(cfg.data["probe"]["token"]),
    }
    # The probe exposes the worker identity via headers when deployed.
    url = cfg.probe_url(target) if cfg.probe_enabled else target
    report.url = url

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [
            pool.submit(_one, url, cfg, timeout, headers)
            for _ in range(concurrency * per_worker)
        ]
        for fut in as_completed(futures):
            status, elapsed, worker, error = fut.result()
            report.total += 1
            report.latencies.append(elapsed)
            if error == "timeout":
                report.timeouts += 1
                report.errors += 1
            elif error:
                report.errors += 1
            elif status is not None:
                report.status_codes[status] += 1
                if 200 <= status < 400:
                    report.ok += 1
                else:
                    report.errors += 1
            if worker:
                report.worker_ids[worker] += 1
    report.wall_seconds = time.perf_counter() - started

    report.notes.append(
        "worker identity comes from the probe headers; without the probe, churn is invisible"
    )
    if report.errors:
        report.notes.append(
            f"{report.errors} error/timeout responses under {concurrency}-way concurrency"
        )
    return report