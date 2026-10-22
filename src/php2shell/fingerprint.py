"""Module B - runtime fingerprinting.

Separates the CLI SAPI from the web SAPI. Never edits the system PATH and never
overwrites XAMPP files: the probe is an additive file in the webroot.
"""
from __future__ import annotations

import json
import platform
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import requests

from .config import AppConfig, PhpBinary
from .logging_config import log_command

_VERSION_LINE_RE = re.compile(r"PHP\s+(\d+\.\d+\.\d+\S*)", re.IGNORECASE)
INI_KEYS = (
    "memory_limit",
    "post_max_size",
    "upload_max_filesize",
    "max_file_uploads",
    "max_input_vars",
    "max_input_nesting_level",
    "session.upload_progress.enabled",
    "session.upload_progress.cleanup",
    "session.use_cookies",
    "session.use_strict_mode",
    "display_errors",
    "log_errors",
    "error_reporting",
    "expose_php",
    "fatal_error_backtraces",
    "opcache.enable",
)


@dataclass
class CliFingerprint:
    name: str
    path: str
    exists: bool
    version: str | None = None
    sapi: str | None = None
    loaded_ini: str | None = None
    ini: dict[str, str | None] = field(default_factory=dict)
    zts: bool | None = None
    arch: str | None = None
    error: str | None = None

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "path": self.path,
            "exists": self.exists,
            "version": self.version,
            "sapi": self.sapi,
            "loaded_ini": self.loaded_ini,
            "ini": self.ini,
            "zts": self.zts,
            "arch": self.arch,
            "error": self.error,
        }


@dataclass
class WebFingerprint:
    url: str
    ok: bool
    status: int | None = None
    data: dict = field(default_factory=dict)
    error: str | None = None

    @property
    def version(self) -> str | None:
        return self.data.get("php_version")

    @property
    def sapi(self) -> str | None:
        return self.data.get("sapi")

    @property
    def ini(self) -> dict:
        return self.data.get("ini", {}) or {}

    def as_dict(self) -> dict:
        return {
            "url": self.url,
            "ok": self.ok,
            "status": self.status,
            "data": self.data,
            "error": self.error,
        }


def _run(cmd: list[str], timeout: float) -> subprocess.CompletedProcess:
    log_command(cmd)
    kwargs: dict = {
        "capture_output": True,
        "text": True,
        "timeout": timeout,
        "encoding": "utf-8",
        "errors": "replace",
    }
    if platform.system() == "Windows":  # pragma: no cover - platform specific
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return subprocess.run(cmd, **kwargs)


def fingerprint_cli(binary: PhpBinary, timeout: float = 20.0) -> CliFingerprint:
    """Record version, SAPI and ini for a configured PHP executable."""
    result = CliFingerprint(name=binary.name, path=str(binary.path), exists=binary.exists())
    if not result.exists:
        resolved = shutil.which(str(binary.path))
        if resolved:
            result.path = resolved
            result.exists = True
        else:
            result.error = "executable not found"
            return result

    try:
        ver = _run([result.path, "-v"], timeout)
        blob = (ver.stdout or "") + (ver.stderr or "")
        m = _VERSION_LINE_RE.search(blob)
        result.version = m.group(1) if m else None
        sapi = re.search(r"\(([^)]*SAPI[^)]*)\)", blob, re.IGNORECASE)
        if sapi:
            result.sapi = sapi.group(1)

        ini_path = _run([result.path, "--ini"], timeout)
        for line in (ini_path.stdout or "").splitlines():
            if "Loaded Configuration File" in line:
                result.loaded_ini = line.split("=>", 1)[-1].strip()
                break

        php_code = ";".join(
            f'echo "{k}=", var_export(ini_get("{k}"), true), "\\n";' for k in INI_KEYS
        )
        php_code += 'echo "PHP_SAPI=", PHP_SAPI, "\\n";'
        php_code += 'echo "ZTS=", (defined("ZEND_THREAD_SAFE") ? "1" : "0"), "\\n";'
        php_code += 'echo "ARCH=", php_uname("m"), "\\n";'
        probe = _run([result.path, "-d", "error_reporting=0", "-r", php_code], timeout)
        for line in (probe.stdout or "").splitlines():
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if key in INI_KEYS:
                result.ini[key] = value
            elif key == "PHP_SAPI":
                result.sapi = value
            elif key == "ZTS":
                result.zts = value == "1"
            elif key == "ARCH":
                result.arch = value
    except subprocess.TimeoutExpired:
        result.error = "php subprocess timed out"
    except OSError as exc:
        result.error = f"cannot execute: {exc}"
    return result


def deploy_probe(cfg: AppConfig, force: bool = False) -> tuple[bool, str]:
    """Copy the probe into the webroot. Additive only."""
    src = cfg.probe_file()
    if not src.is_file():
        return False, f"probe source missing: {src}"
    dst = cfg.probe_deploy_path()

    token = str(cfg.data["probe"]["token"])
    rendered = src.read_text(encoding="utf-8").replace("__P2S_TOKEN__", token)

    if dst.is_file() and not force:
        try:
            if dst.read_text(encoding="utf-8") == rendered:
                return True, f"already current: {dst}"
        except OSError:
            pass

    try:
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(rendered, encoding="utf-8")
    except OSError as exc:
        return False, f"cannot write {dst}: {exc}"
    return True, f"deployed: {dst}"


def fingerprint_web(
    base_url: str, cfg: AppConfig, mode: str = "status", timeout: float | None = None
) -> WebFingerprint:
    """Read the probe over HTTP. Returns ok=False instead of raising."""
    url = cfg.probe_url(base_url)
    if mode != "status":
        url = f"{url}?mode={mode}"
    headers = {str(cfg.data["probe"]["token_header"]): str(cfg.data["probe"]["token"])}
    result = WebFingerprint(url=url, ok=False)
    try:
        resp = requests.get(
            url,
            headers=headers,
            timeout=timeout or cfg.request_timeout,
            allow_redirects=False,
        )
        result.status = resp.status_code
        if resp.status_code == 403:
            result.error = "probe rejected the token"
            return result
        if resp.status_code != 200:
            result.error = f"unexpected status {resp.status_code}"
            return result
        result.data = resp.json()
        result.ok = True
    except requests.Timeout:
        result.error = "probe timed out"
    except requests.RequestException as exc:
        result.error = f"probe request failed: {exc}"
    except json.JSONDecodeError:
        result.error = "probe did not return JSON (is PHP executing?)"
    return result