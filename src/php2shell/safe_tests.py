"""Module C - documented, non-destructive local tests.

Layers:
  0 baseline reachability
  1 probe fingerprint (real web SAPI + ini)
  2 controlled OOM + worker-reuse diagnostic
  3 Set-Cookie / PHPSESSID leak heuristic (experimental)

None of these prove RCE. The interpretation strings are taken from the published
safe-lab methodology.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field

import requests

from .config import AppConfig
from .fingerprint import WebFingerprint, fingerprint_web
from .target_validation import validate_target

OOM_SESSION_FIELD = "PHP_SESSION_UPLOAD_PROGRESS"


@dataclass
class TestResult:
    name: str
    layer: int
    ran: bool
    passed: bool | None
    expected: str
    actual: str
    status: str = "implemented"
    evidence: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "layer": self.layer,
            "ran": self.ran,
            "passed": self.passed,
            "expected": self.expected,
            "actual": self.actual,
            "status": self.status,
            "evidence": self.evidence,
            "notes": self.notes,
        }


def _skipped(name: str, layer: int, why: str, expected: str = "") -> TestResult:
    return TestResult(name=name, layer=layer, ran=False, passed=None,
                      expected=expected, actual=why, notes=[why])


def build_multipart(fields: int, nesting: int, *, prime_session: bool,
                    session_id: str, boundary: str | None = None) -> tuple[bytes, str]:
    """Multipart body of empty-file parts with deeply nested field names.

    Empty file parts do not count towards max_file_uploads but still create six
    $_FILES entries each; nesting multiplies the array work. This is the
    documented way to reach OOM while staying under post_max_size.
    """
    boundary = boundary or f"----p2s{secrets.token_hex(8)}"
    parts: list[str] = []

    if prime_session:
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; '
            f'name="{OOM_SESSION_FIELD}"\r\n\r\np2s\r\n'
        )

    nest = "".join(f"[a{i}]" for i in range(max(0, nesting)))
    for i in range(max(1, fields)):
        name = f"f{nest}[{i}]"
        parts.append(
            f'--{boundary}\r\n'
            f'Content-Disposition: form-data; name="{name}"; filename=""\r\n'
            f'Content-Type: application/octet-stream\r\n\r\n\r\n'
        )

    parts.append(f"--{boundary}--\r\n")
    return "".join(parts).encode("utf-8"), f"multipart/form-data; boundary={boundary}"


def _post_multipart(url: str, body: bytes, content_type: str, cfg: AppConfig,
                    cookies: dict | None = None, timeout: float | None = None):
    headers = {
        str(cfg.data["probe"]["token_header"]): str(cfg.data["probe"]["token"]),
        "Content-Type": content_type,
    }
    return requests.post(
        url,
        data=body,
        headers=headers,
        cookies=cookies or {},
        timeout=timeout or max(cfg.request_timeout, 30.0),
        allow_redirects=False,
    )


# ---------------------------------------------------------------------------


def baseline(target: str, cfg: AppConfig) -> TestResult:
    name = "baseline reachability"
    try:
        resp = requests.get(target, timeout=cfg.request_timeout, allow_redirects=False)
    except requests.RequestException as exc:
        return TestResult(name, 0, True, False, "HTTP response", f"failed: {exc}",
                          evidence={"error": str(exc)})
    return TestResult(
        name, 0, True, True, "HTTP response",
        f"HTTP {resp.status_code} in {resp.elapsed.total_seconds()*1000:.0f} ms",
        evidence={"status": resp.status_code},
    )


def probe_fingerprint(target: str, cfg: AppConfig) -> tuple[TestResult, WebFingerprint]:
    name = "web runtime fingerprint"
    wf = fingerprint_web(target, cfg, mode="status")
    if not wf.ok:
        res = TestResult(name, 1, True, False, "probe JSON", wf.error or "unknown failure",
                         evidence=wf.as_dict(),
                         notes=["deploy the probe or check probe.token / probe.webroot"])
        return res, wf
    ini = wf.ini
    res = TestResult(
        name, 1, True, True, "probe JSON",
        f"PHP {wf.version} on {wf.sapi}",
        evidence=wf.as_dict(),
        notes=[
            "the probe reports the real web SAPI, which the CLI binary cannot show",
            f"session.upload_progress.enabled={ini.get('session.upload_progress.enabled')}",
            f"memory_limit={ini.get('memory_limit')}",
        ],
    )
    return res, wf

def oom_script_driven(target: str, cfg: AppConfig) -> TestResult:
    """Layer 2b. Deterministic OOM from inside PHP, not from parsing.

    The parse-time flood can be defeated by a large memory_limit; this variant
    asks the probe to allocate until it fatals, so the OOM is guaranteed when a
    finite limit exists.
    """
    name = "controlled OOM (script-driven)"
    if not cfg.probe_enabled:
        return _skipped(name, 2, "probe disabled")

    url = cfg.probe_url(target) + "?mode=oom"
    headers = {str(cfg.data["probe"]["token_header"]): str(cfg.data["probe"]["token"])}
    try:
        resp = requests.get(url, headers=headers, timeout=max(cfg.request_timeout, 60.0),
                            allow_redirects=False)
    except requests.RequestException as exc:
        return TestResult(name, 2, True, None, "a fatal memory error",
                          f"request failed: {exc}", evidence={"error": str(exc)})

    body = resp.text or ""
    fatal = "Allowed memory size" in body or "Out of memory" in body
    survived = "oom_survived" in body
    if survived and not fatal:
        actual = "script survived: memory_limit is likely unlimited"
    elif fatal:
        actual = "fatal memory error observed"
    else:
        actual = f"HTTP {resp.status_code}, no marker"

    return TestResult(
        name, 2, True, None,
        "a fatal memory error when a finite memory_limit exists",
        actual,
        evidence={"status": resp.status_code, "body_head": body[:300]},
        notes=[
            "oom_survived with no fatal means memory_limit=-1 (the 109618 mitigation)",
            "still does not prove the use-after-free",
        ],
    )

def oom_and_worker_reuse(target: str, cfg: AppConfig) -> list[TestResult]:
    """Layer 2. Sends deliberately fatal requests, then observes recovery."""
    results: list[TestResult] = []
    ocfg = cfg.data["tests"]["oom"]
    if not cfg.probe_enabled or not ocfg.get("enabled", True):
        results.append(_skipped("controlled OOM", 2, "disabled in config"))
        return results

    before = fingerprint_web(target, cfg, mode="status")
    if not before.ok:
        results.append(_skipped("controlled OOM", 2, f"probe unavailable: {before.error}"))
        return results

    worker_before = (before.data.get("pid"), before.data.get("thread_id"))
    session_id = secrets.token_hex(16)
    body, ctype = build_multipart(
        int(ocfg["fields"]), int(ocfg["nesting"]), prime_session=True, session_id=session_id
    )

    url = cfg.probe_url(target)
    try:
        resp = _post_multipart(url, body, ctype, cfg, cookies={"PHPSESSID": session_id})
        status = resp.status_code
        body_text = resp.text[:400]
    except requests.RequestException as exc:
        status, body_text = None, f"request error: {exc}"

    fatal_seen = "Allowed memory size" in body_text or "Out of memory" in body_text
    results.append(TestResult(
        "controlled OOM (multipart flood)", 2, True, fatal_seen or status in (500, 200),
        "a fatal memory error, or a truncated 200/500",
        f"HTTP {status}; fatal marker {'present' if fatal_seen else 'absent'}",
        status="implemented",
        evidence={"status": status, "fields": ocfg["fields"], "nesting": ocfg["nesting"],
                  "body_head": body_text},
        notes=[
            "HTTP 200 with a truncated body is normal: output is flushed before the fatal",
            "an isolated OOM does not prove the CVE",
        ],
    ))

    # --- INSERT HERE: deterministic OOM from inside PHP -------------------
    results.append(oom_script_driven(target, cfg))
    # ---------------------------------------------------------------------

    if not ocfg.get("confirm_worker_reuse", True):
        return results

    after = fingerprint_web(target, cfg, mode="status")
    if not after.ok:
        results.append(TestResult(
            "worker reuse after OOM", 2, True, None, "a later probe response",
            f"probe did not answer: {after.error}",
            notes=["WORKER_REPLACED_OR_NOT_RESAMPLED / inconclusive"],
        ))
        return results

    worker_after = (after.data.get("pid"), after.data.get("thread_id"))
    same = worker_before == worker_after and worker_before[0] is not None
    results.append(TestResult(
        "worker reuse after OOM", 2, True, same,
        "the same worker serves the next request",
        f"before={worker_before} after={worker_after}",
        notes=[
            "RECOVERED_SAME_WORKER: the same process/thread survived a benign OOM. "
            "This neither proves nor disproves PHP2Shell."
            if same else
            "WORKER_REPLACED_OR_NOT_RESAMPLED: inconclusive, especially with several workers",
            "on Windows mpm_winnt all requests share one PID; thread_id is the real signal",
        ],
    ))
    return results


def leak_inspection(target: str, cfg: AppConfig) -> TestResult:
    """Layer 3 (experimental). Heuristic on the PHPSESSID Set-Cookie shape."""
    name = "PHPSESSID leak heuristic"
    lcfg = cfg.data["tests"]["leak"]
    if not cfg.probe_enabled or not lcfg.get("enabled", True):
        return _skipped(name, 3, "disabled in config")

    cookie_name = str(lcfg.get("cookie_name", "PHPSESSID"))
    session_id = secrets.token_hex(16)
    body, ctype = build_multipart(4, 2, prime_session=True, session_id=session_id)
    url = cfg.probe_url(target)
    try:
        resp = _post_multipart(url, body, ctype, cfg, cookies={cookie_name: session_id})
    except requests.RequestException as exc:
        return TestResult(name, 3, True, None, "a Set-Cookie header",
                          f"request failed: {exc}", status="experimental")

    cookies = resp.headers.get("Set-Cookie", "")
    value = ""
    for chunk in cookies.split(","):
        if cookie_name in chunk:
            value = chunk.split("=", 1)[-1].split(";")[0]
            break

    import re as _re
    normal = bool(_re.fullmatch(r"[A-Za-z0-9,\-]{22,48}", value or ""))
    suspicious = bool(value) and not normal

    return TestResult(
        name, 3, True, None,
        "a normal session id, or a longer percent-encoded value",
        f"cookie length={len(value)} shape={'normal' if normal else 'unusual'}",
        status="experimental",
        evidence={"set_cookie": cookies[:512], "value_length": len(value)},
        notes=[
            "an unusually long or percent-encoded PHPSESSID is consistent with reclaimed "
            "worker memory being URL-encoded into the cookie",
            "heuristic only: it does not prove the leak, and requires display_errors=On, "
            "a low memory_limit and a single worker",
        ],
    )


def run_all(target: str, cfg: AppConfig, *, include_oom: bool = True,
            include_leak: bool = True) -> list[TestResult]:
    validation = validate_target(target, cfg)
    if not validation.allowed:
        return [_skipped("target validation", 0, f"rejected: {validation.reason}")]

    results = [baseline(target, cfg)]
    fp, _ = probe_fingerprint(target, cfg)
    results.append(fp)
    if include_oom:
        results.extend(oom_and_worker_reuse(target, cfg))
    if include_leak:
        results.append(leak_inspection(target, cfg))
    return results