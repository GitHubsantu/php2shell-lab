"""Scan and recon. Read-only, no auth bypass, no traversal, no file access."""
from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field

import requests

from .config import AppConfig
from .target_validation import validate_target

INTERESTING_HEADERS = (
    "server",
    "x-powered-by",
    "x-php-version",
    "content-type",
    "date",
    "via",
    "x-cache",
    "strict-transport-security",
)


@dataclass
class HttpObservation:
    url: str
    ok: bool
    status: int | None = None
    elapsed_ms: float | None = None
    headers: dict[str, str] = field(default_factory=dict)
    indicators: list[str] = field(default_factory=list)
    error: str | None = None

    def as_dict(self) -> dict:
        return {
            "url": self.url,
            "ok": self.ok,
            "status": self.status,
            "elapsed_ms": round(self.elapsed_ms, 2) if self.elapsed_ms is not None else None,
            "headers": self.headers,
            "indicators": self.indicators,
            "error": self.error,
        }


def _request(url: str, cfg: AppConfig, timeout: float | None = None) -> HttpObservation:
    obs = HttpObservation(url=url, ok=False)
    started = time.perf_counter()
    try:
        resp = requests.get(
            url,
            timeout=timeout or cfg.request_timeout,
            allow_redirects=False,
            headers={"User-Agent": "php2shell-lab/0.1 (local research)"},
        )
        obs.elapsed_ms = (time.perf_counter() - started) * 1000.0
        obs.status = resp.status_code
        obs.ok = True
        obs.headers = {k.lower(): v for k, v in resp.headers.items()}
        if resp.status_code in (301, 302, 303, 307, 308):
            obs.indicators.append(
                f"redirect to {resp.headers.get('Location', '?')} (not followed)"
            )
        powered = obs.headers.get("x-powered-by", "")
        if "php" in powered.lower():
            obs.indicators.append(f"X-Powered-By discloses: {powered}")
        else:
            obs.indicators.append("no X-Powered-By (expose_php may be Off)")
        server = obs.headers.get("server", "")
        if server:
            obs.indicators.append(f"Server banner: {server}")
        if "php" in server.lower():
            obs.indicators.append("PHP version visible in the Server header")
    except requests.Timeout:
        obs.error = "timeout"
        obs.elapsed_ms = (time.perf_counter() - started) * 1000.0
    except requests.RequestException as exc:
        obs.error = str(exc)
        obs.elapsed_ms = (time.perf_counter() - started) * 1000.0
    return obs


def scan(target: str, cfg: AppConfig) -> dict:
    """Reachability, basic response info, observable runtime indicators."""
    validation = validate_target(target, cfg)
    result: dict = {"validation": validation.as_dict(), "observation": None, "notes": []}

    if not validation.allowed:
        result["notes"].append(f"target rejected: {validation.reason}")
        return result

    obs = _request(target, cfg)
    result["observation"] = obs.as_dict()
    result["notes"].append(
        "a version indicator is not confirmation: vendor backports keep the version string"
    )
    return result


def recon(target: str, cfg: AppConfig, paths: list[str] | None = None) -> dict:
    """Headers, status codes, timing and explicitly disclosed runtime info."""
    validation = validate_target(target, cfg)
    result: dict = {"validation": validation.as_dict(), "probes": [], "timing": {}, "notes": []}
    if not validation.allowed:
        result["notes"].append(f"target rejected: {validation.reason}")
        return result

    base = target.rstrip("/")
    candidates = paths or [""] + [p for p in cfg.data["tests"]["baseline_paths"] if p != "/"]
    seen: set[str] = set()

    for path in candidates:
        url = base + path
        if url in seen:
            continue
        seen.add(url)
        obs = _request(url, cfg)
        result["probes"].append(obs.as_dict())

    latencies = [
        p["elapsed_ms"] for p in result["probes"] if p.get("elapsed_ms") is not None
    ]
    if latencies:
        result["timing"] = {
            "samples": len(latencies),
            "min_ms": round(min(latencies), 2),
            "max_ms": round(max(latencies), 2),
            "median_ms": round(statistics.median(latencies), 2),
        }
    result["notes"].append("no authentication, traversal or file-access tests performed")
    return result