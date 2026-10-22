"""Optional deep mode: shell out to an external public PoC when present.

Off by default in spirit: the tool never silently runs an exploit. Every
subprocess command line is logged before execution.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .config import AppConfig
from .logging_config import log_command


@dataclass
class DeepResult:
    ran: bool
    command: list[str]
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    notes: list[str] | None = None

    def as_dict(self) -> dict:
        return {
            "ran": self.ran,
            "command": self.command,
            "returncode": self.returncode,
            "stdout": self.stdout[-8000:],
            "stderr": self.stderr[-4000:],
            "notes": self.notes or [],
        }


def run_poc(target: str, cfg: AppConfig, poc_path: str | None = None,
            command: str | None = None) -> DeepResult:
    dcfg = cfg.data["deep_mode"]
    poc = poc_path or dcfg.get("poc_path")
    notes: list[str] = []

    if not poc:
        return DeepResult(False, [], notes=["deep_mode.poc_path is not set"])

    poc_file = Path(str(poc))
    if not poc_file.is_file():
        return DeepResult(False, [], notes=[f"PoC not found: {poc_file}"])

    python = shutil.which("python3") or shutil.which("python") or "python"
    cmd = [python, str(poc_file), "-u", target, "-c", command or str(dcfg.get("command", "id"))]
    cmd.extend(str(a) for a in dcfg.get("extra_args", []))

    log_command(cmd)
    notes.append("deep mode invokes an external script; the tool does not reimplement the chain")
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=180,
            encoding="utf-8", errors="replace",
        )
    except subprocess.TimeoutExpired:
        return DeepResult(False, cmd, notes=notes + ["PoC timed out after 180 s"])
    except OSError as exc:
        return DeepResult(False, cmd, notes=notes + [f"cannot execute PoC: {exc}"])

    return DeepResult(True, cmd, proc.returncode, proc.stdout or "", proc.stderr or "", notes)