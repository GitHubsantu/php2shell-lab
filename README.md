# PHP2Shell Local Research Framework

A small, honest CLI toolkit for investigating **CVE-2026-109618** and
**CVE-2026-109619** ("PHP2Shell") against a local lab.

Built for **Windows 11 + XAMPP**, with optional isolated Linux support.
Default target is loopback only. No reverse shells, no persistence, no
credential theft, no exploit chaining against third parties.

> **The core rule:** a version string is *evidence*, never proof. Distro
> packages keep the upstream version number after backporting a fix, and an
> affected range does not mean the published chain will fire on your box.

---

## What this tool actually proves

| Layer | Capability | Command | Windows/XAMPP | Linux lab |
|---|---|---|---|---|
| 0 | Reachability | `--scan` | works | works |
| 1 | Real web SAPI + php.ini | `--check` / `--local-test` | works (probe) | works |
| 2 | OOM handling + worker survival | `--local-test --oom` | likely works | works |
| 3 | `PHPSESSID` leak heuristic | `--local-test --leak` | experimental | works in known configs |
| 4 | Full RCE | `--deep` (external PoC) | **unsupported** | experimental |

Layers 0–2 are real and safe. Layer 3 is a heuristic. Layer 4 needs
per-build ELF offsets, so on Windows it needs an external PoC plus a Linux
target — the tool does not reimplement the chain.

---

## Requirements

- Python 3.10+
- XAMPP (Apache + PHP) already installed and running
- Windows 11, PowerShell 5.1+ or Command Prompt

Dependencies: `requests`, `PyYAML`, `rich`. Dev: `pytest`.

---

## Install

**PowerShell**

```powershell
cd E:\php2shell-lab
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"