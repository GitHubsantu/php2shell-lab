"""Configuration loading, validation and defaults."""
from __future__ import annotations

import copy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

DEFAULTS: dict[str, Any] = {
    "framework": {"version": "0.1.0"},
    "targets": {
        "default": "http://127.0.0.1:8088",
        "request_timeout": 10.0,
        "allow_loopback": True,
        "allow_private": False,
        "allow_public": False,
        "allowed_hosts": [],
        "allowed_cidrs": [],
        "follow_redirects_within_lab": False,
        "max_redirect_hops": 3,
    },
    "php": {
        "binaries": [
            {
                "name": "xampp",
                "path": r"E:\xampp\php\php.exe",
                "label": "XAMPP current PHP",
            }
        ],
        "expected_sapi": "apache2handler",
        "subprocess_timeout": 20.0,
    },
    "probe": {
        "enabled": True,
        "filename": "php2shell-lab.php",
        "token": "p2s-local-lab-token",
        "webroot": r"E:\xampp\htdocs",
        "url_path": "/php2shell-lab.php",
        "auto_deploy": True,
        "token_header": "X-P2S-Token",
    },
    "tests": {
        "baseline_paths": ["/", "/index.php"],
        "oom": {
            "enabled": True,
            "fields": 900,
            "nesting": 3,
            "block_mib": 1,
            "extra_blocks": 6,
            "max_blocks": 2048,
            "confirm_worker_reuse": True,
            "expect_fatal": True,
        },
        "leak": {"enabled": True, "cookie_name": "PHPSESSID"},
    },
    "race": {"concurrency": 12, "requests_per_worker": 20, "timeout": 20.0},
    "deep_mode": {
        "enabled": True,
        "poc_path": None,
        "command": "id",
        "extra_args": [],
    },
    "redaction": {
        "headers": ["set-cookie", "cookie", "authorization", "x-p2s-token"],
        "cookie_names": ["PHPSESSID"],
        "keep_header_prefix": 16,
    },
    "reporting": {"dir": "reports", "include_raw_headers": True},
    "logging": {"dir": "logs", "level": "INFO", "max_bytes": 1048576, "backup_count": 5},
}


class ConfigError(RuntimeError):
    """Raised when configuration cannot be loaded or is invalid."""


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


@dataclass(frozen=True)
class PhpBinary:
    name: str
    path: Path
    label: str = ""

    def exists(self) -> bool:
        return self.path.is_file()


@dataclass
class AppConfig:
    """Merged configuration with typed accessors."""

    root: Path
    data: dict[str, Any]
    source: Path | None = None

    # -- targets -----------------------------------------------------------
    @property
    def target(self) -> str:
        return str(self.data["targets"]["default"])

    @property
    def request_timeout(self) -> float:
        return float(self.data["targets"]["request_timeout"])

    # -- php ---------------------------------------------------------------
    def php_binaries(self) -> list[PhpBinary]:
        out: list[PhpBinary] = []
        for entry in self.data["php"]["binaries"]:
            out.append(
                PhpBinary(
                    name=str(entry["name"]),
                    path=Path(str(entry["path"])),
                    label=str(entry.get("label", "")),
                )
            )
        return out

    def php_binary(self, name: str | None = None) -> PhpBinary | None:
        bins = self.php_binaries()
        if not bins:
            return None
        if name is None:
            return bins[0]
        for b in bins:
            if b.name == name:
                return b
        return None

    # -- probe -------------------------------------------------------------
    @property
    def probe_enabled(self) -> bool:
        return bool(self.data["probe"]["enabled"])

    def probe_url(self, base: str) -> str:
        base = base.rstrip("/")
        return base + str(self.data["probe"]["url_path"])

    def probe_file(self) -> Path:
        return self.root / "config" / "probe" / str(self.data["probe"]["filename"])

    def probe_deploy_path(self) -> Path:
        return Path(str(self.data["probe"]["webroot"])) / str(self.data["probe"]["filename"])

    # -- dirs --------------------------------------------------------------
    def report_dir(self) -> Path:
        d = self.root / str(self.data["reporting"]["dir"])
        d.mkdir(parents=True, exist_ok=True)
        return d

    def log_dir(self) -> Path:
        d = self.root / str(self.data["logging"]["dir"])
        d.mkdir(parents=True, exist_ok=True)
        return d


def _validate(data: dict[str, Any]) -> None:
    if not isinstance(data.get("targets"), dict):
        raise ConfigError("targets: must be a mapping")
    if not data["targets"].get("default"):
        raise ConfigError("targets.default must not be empty")
    if float(data["targets"].get("request_timeout", 0)) <= 0:
        raise ConfigError("targets.request_timeout must be > 0")
    if not isinstance(data.get("race"), dict):
        raise ConfigError("race: must be a mapping")
    if int(data["race"].get("concurrency", 0)) < 1:
        raise ConfigError("race.concurrency must be >= 1")
    for entry in data.get("php", {}).get("binaries", []):
        if not entry.get("name") or not entry.get("path"):
            raise ConfigError("each php.binaries entry needs name and path")


def load_config(path: Path | None = None, root: Path | None = None) -> AppConfig:
    """Load YAML config merged over defaults.

    Missing file is not an error: defaults apply and a warning is not raised,
    because the lab may legitimately run before the config is customised.
    """
    root = (root or Path(__file__).resolve().parents[2]).resolve()
    merged = copy.deepcopy(DEFAULTS)

    if path is None:
        candidate = root / "config" / "php2shell.yaml"
        path = candidate if candidate.is_file() else None
    elif not path.is_file():
        raise ConfigError(f"config file not found: {path}")

    if path is not None:
        try:
            loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:  # pragma: no cover - depends on file
            raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
        if not isinstance(loaded, dict):
            raise ConfigError(f"{path} must contain a YAML mapping at the top level")
        merged = _deep_merge(merged, loaded)

    _validate(merged)
    return AppConfig(root=root, data=merged, source=path)