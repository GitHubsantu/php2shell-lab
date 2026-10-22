"""JSON and Markdown reports with header/cookie redaction."""
from __future__ import annotations

import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .config import AppConfig

SENSITIVE_DEFAULT = {"set-cookie", "cookie", "authorization"}


def redact_headers(headers: dict[str, str], cfg: AppConfig) -> dict[str, str]:
    names = {str(n).lower() for n in cfg.data["redaction"]["headers"]} or SENSITIVE_DEFAULT
    keep = int(cfg.data["redaction"].get("keep_header_prefix", 16))
    out: dict[str, str] = {}
    for key, value in (headers or {}).items():
        lowered = key.lower()
        if lowered in names:
            if lowered == "set-cookie":
                out[key] = _redact_set_cookie(value, cfg)
            elif len(value) > keep:
                out[key] = value[:keep] + "..."
            else:
                out[key] = value
        else:
            out[key] = value
    return out


def _redact_set_cookie(value: str, cfg: AppConfig) -> str:
    cookie_names = [str(c).lower() for c in cfg.data["redaction"].get("cookie_names", [])]
    pieces = []
    for chunk in str(value).split(","):
        head = chunk.split(";", 1)[0].strip()
        if "=" not in head:
            pieces.append(head)
            continue
        name, _, val = head.partition("=")
        if name.strip().lower() in cookie_names or "sess" in name.lower():
            pieces.append(f"{name}=<{len(val)} chars>")
        else:
            pieces.append(f"{name}={val[:12]}...")
    return "; ".join(pieces)


def environment_snapshot(cfg: AppConfig) -> dict[str, Any]:
    return {
        "framework_version": __version__,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "config_source": str(cfg.source) if cfg.source else None,
        "target_default": cfg.target,
        "php_binaries": [
            {"name": b.name, "path": str(b.path), "exists": b.exists()}
            for b in cfg.php_binaries()
        ],
        "note": "redaction applied to Set-Cookie, Cookie, Authorization and the probe token header",
    }


def build_report(cfg: AppConfig, *, mode: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "framework": "php2shell-lab",
        "mode": mode,
        "environment": environment_snapshot(cfg),
        "payload": payload,
        "disclaimer": (
            "Version-based evidence only. No RCE or shell access is claimed unless an "
            "external proof is present in this report."
        ),
    }


def _stamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def write_json(cfg: AppConfig, report: dict[str, Any], stem: str | None = None) -> Path:
    path = cfg.report_dir() / f"{stem or report['mode']}-{_stamp()}.json"
    path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return path


def write_markdown(cfg: AppConfig, report: dict[str, Any], stem: str | None = None) -> Path:
    path = cfg.report_dir() / f"{stem or report['mode']}-{_stamp()}.md"
    env = report["environment"]
    lines: list[str] = [
        "# PHP2Shell lab report",
        "",
        f"- mode: `{report['mode']}`",
        f"- generated (UTC): {env['generated_utc']}",
        f"- framework: v{env['framework_version']}",
        f"- python: {env['python']} on {env['platform']}",
        f"- default target: `{env['target_default']}`",
        "",
        "> " + report["disclaimer"],
        "",
    ]

    payload = report.get("payload", {})

    verdict = payload.get("verdict") or payload.get("finding", {}).get("verdict")
    if verdict:
        lines += ["## Verdict", "", f"**{verdict}**", ""]
        finding = payload.get("finding", payload)
        for reason in finding.get("reasons", []):
            lines.append(f"- {reason}")
        if finding.get("limitations"):
            lines += ["", "### Limitations", ""]
            lines += [f"- {lim}" for lim in finding["limitations"]]
        lines.append("")

    if payload.get("environment"):
        lines += ["## Runtime", "", "```json",
                  json.dumps(payload["environment"], indent=2, default=str), "```", ""]

    tests = payload.get("tests")
    if tests:
        lines += ["## Tests", "", "| test | layer | ran | result | expected | actual |",
                  "|---|---|---|---|---|---|"]
        for t in tests:
            passed = {True: "pass", False: "fail", None: "n/a"}.get(t.get("passed"), "?")
            lines.append(
                f"| {t.get('name')} | {t.get('layer')} | {t.get('ran')} | {passed} | "
                f"{t.get('expected')} | {t.get('actual')} |"
            )
        lines.append("")
        for t in tests:
            if t.get("notes"):
                lines.append(f"**{t.get('name')}**")
                lines += [f"- {n}" for n in t["notes"]]
                lines.append("")

    remediation = payload.get("remediation")
    if remediation:
        lines += ["## Remediation", ""]
        lines += [f"- {r}" for r in remediation]
        lines.append("")

    lines += ["## Raw payload", "", "```json",
              json.dumps(payload, indent=2, default=str), "```", ""]
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def write_both(cfg: AppConfig, report: dict[str, Any], stem: str | None = None) -> tuple[Path, Path]:
    return write_json(cfg, report, stem), write_markdown(cfg, report, stem)