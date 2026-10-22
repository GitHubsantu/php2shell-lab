# PHP2Shell Local Research Framework

A small, honest CLI toolkit for investigating **CVE-2026-109618** and
**CVE-2026-109619** ("PHP2Shell") against a local lab.

Built for **Windows 11 + XAMPP**, with optional isolated Linux support.
Default target is loopback only. No reverse shells, no persistence, no
credential theft, no exploit chaining against third parties.

> **The core rule:** a version string is *evidence*, never proof. Distro
> packages keep the upstream version number after backporting a fix, and an
> affected range does not mean the published chain will fire on your box.

Verified on Windows 11 + XAMPP (Apache `mod_php`), Python 3.14.

---

## Contents

- [What this tool actually proves](#what-this-tool-actually-proves)
- [Requirements](#requirements)
- [Install](#install)
- [Quickstart](#quickstart)
- [Commands](#commands)
- [Configuration](#configuration)
- [Probe lifecycle](#probe-lifecycle)
- [Interpretation](#interpretation)
- [Reports](#reports)
- [Tests](#tests)
- [Troubleshooting](#troubleshooting)
- [Remediation](#remediation)
- [Limitations](#limitations)
- [Known traps](#known-traps)
- [Acceptable use](#acceptable-use)
- [Sources](#sources)

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
- XAMPP (Apache + PHP) installed and running
- Windows 11, PowerShell 5.1+ or Command Prompt

Dependencies: `requests`, `PyYAML`, `rich`. Dev: `pytest`.

---

## Install

Adjust the path if your checkout is elsewhere.

**PowerShell**

```powershell
cd E:\cyberProject\php2shell-lab
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

The prompt must change to `(.venv) PS E:\cyberProject\php2shell-lab>`. If
activation is blocked:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

Then install. Always use `python -m pip` so you cannot hit the wrong pip:

```powershell
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

**Command Prompt**

```cmd
cd /d E:\cyberProject\php2shell-lab
py -3 -m venv .venv
.venv\Scripts\activate.bat
python -m pip install -e ".[dev]"
```

**Verify**

```powershell
python -c "import sys; print(sys.executable)"   # must point inside .venv
python php2shell.py --version
python -m pytest
```

If the editable install fails, the shim still works — install the deps
directly:

```powershell
python -m pip install requests PyYAML rich pytest
python php2shell.py --version
```

---

## Quickstart

```powershell
# 1. confirm Apache is serving PHP
python php2shell.py --target http://127.0.0.1:8088 --scan

# 2. drop the read-only probe into htdocs, then assess
python php2shell.py --deploy-probe --target http://127.0.0.1:8088 --check

# 3. run the safe suite
python php2shell.py --local-test --oom --leak

# 4. write reports
python php2shell.py --report

# 5. interactive menu
python php2shell.py --menu
```

---

## Commands

| Flag | Purpose |
|---|---|
| `--help` | usage, research modes, safety notes |
| `--version` | framework version, modules, maturity |
| `--scan` | reachability, response info, runtime indicators |
| `--check` | evidence-based verdict against verified advisories |
| `--recon` | headers, status codes, response timing |
| `--local-test` | baseline + probe + optional OOM/leak/deep |
| `--race` | concurrency, latency percentiles, worker churn |
| `--report` | timestamped JSON + Markdown |
| `--menu` | interactive menu |

Modifiers: `--target`, `--config`, `--php-bin`, `--deploy-probe`, `--no-probe`,
`--oom`, `--leak`, `--deep`, `--poc`, `--concurrency`, `--requests`,
`--timeout`, `--allow-public`, `--json`, `--quiet`.

### Verdict vocabulary

`--check` returns exactly one of:

- **Not assessed** — target did not answer
- **Potentially affected** — version inside an affected range
- **No evidence detected** — version outside every known affected branch
- **Fixed build identified** — version at or above the fixed release
- **Manual verification required** — no version disclosed, or a vendor
  package suffix suggests a backport

Every verdict ships with its `reasons` and `limitations`.

---

## Configuration

`config/php2shell.yaml`. Paths default to an `E:\xampp` install.

Key sections: `targets` (allow-list and timeouts), `php.binaries`,
`probe` (webroot, token), `tests`, `race`, `deep_mode`, `redaction`,
`reporting`, `logging`.

To compare vulnerable vs patched without touching XAMPP, unpack a fixed PHP
somewhere else and add a second entry:

```yaml
php:
  binaries:
    - name: xampp
      path: 'E:\xampp\php\php.exe'
    - name: patched
      path: 'E:\php-8.2.35\php.exe'
```

Then `--php-bin patched`.

### Widening the target scope

Loopback is allowed by default. Everything else needs explicit opt-in:

```yaml
targets:
  allowed_cidrs: ["127.0.0.0/8", "192.168.56.0/24"]  # isolated VM
  allow_private: true
```

Redirects are not followed outside the lab (`follow_redirects_within_lab`).

---

## Probe lifecycle

`config/probe/php2shell-lab.php` is **additive**. It is copied to
`E:\xampp\htdocs\php2shell-lab.php` with the token substituted.

- `GET ?mode=status` → JSON: real web SAPI, PHP version, ZTS flag, PID,
  thread id, and a php.ini subset.
- `GET ?mode=oom` → flushes a line, then allocates until the memory limit
  fatals. Demonstrates fatal-error handling, not the CVE.

The probe is token-gated via the `X-P2S-Token` header. The default token is a
disposable lab credential — do not reuse it. Delete the file from `htdocs`
when done:

```powershell
Remove-Item E:\xampp\htdocs\php2shell-lab.php
```

Verify it independently:

```powershell
Invoke-RestMethod -Headers @{'X-P2S-Token'='p2s-local-lab-token'} `
  http://127.0.0.1:8088/php2shell-lab.php
```

---

## Interpretation

**OOM test**

| Result | Means |
|---|---|
| same PID/thread before and after | `RECOVERED_SAME_WORKER` — worker survived a benign OOM. Neither proves nor disproves PHP2Shell. |
| different PID/thread | `WORKER_REPLACED_OR_NOT_RESAMPLED` — inconclusive with several workers |
| no response afterwards | `FAILED` — check Apache logs |

On Windows `mpm_winnt` all requests share one PID and different threads are
used per request, so a changed thread id here is normal, not a failure.

**Leak test** — an unusually long or percent-encoded `PHPSESSID` is
*consistent with* reclaimed worker memory. It is a heuristic, and it needs
`display_errors=On`, a low `memory_limit` and a single worker.

---

## Reports

`--report` writes `reports/full-<timestamp>.json` and `.md`.

Redacted: `Set-Cookie` (cookie values replaced by length), `Cookie`,
`Authorization`, `X-P2S-Token`. Everything else is kept.

---

## Tests

```powershell
python -m pytest
python -m pytest -v tests/test_cve_intelligence.py
```

Never call bare `pytest` from PowerShell — the console script may not be on
PATH even when the package is installed.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `'php2shell' is not a package` | `src/php2shell/__init__.py` missing, so `php2shell.py` shadows the package | create the file; the shim also self-heals |
| `pytest: not recognized` | venv not active, so `Scripts` is not on PATH | activate the venv, then use `python -m pytest` |
| `Defaulting to user installation because normal site-packages is not writeable` | venv not active | use `.\.venv\Scripts\Activate.ps1`, then `python -m pip` |
| `project.readme must be valid exactly by one definition` | `readme`/`license` keys collide in `pyproject.toml` | drop both keys, or use `readme = { file = "README.md", content-type = "text/markdown" }` |
| `target error: unsupported scheme` | bad URL | use `http://` or `https://` |
| `rejected: not loopback and not allow-listed` | non-loopback target | add to `allowed_hosts` / `allowed_cidrs`, or `--allow-public` |
| baseline fails, `ConnectionRefused` | Apache not running | start Apache in the XAMPP control panel |
| `probe: cannot write ...` | htdocs not writable | run as admin, or set `probe.webroot` |
| `probe rejected the token` | stale deployed copy | `--deploy-probe` again, or delete the file in htdocs |
| `probe did not return JSON` | Apache serving `.php` as text | check the PHP handler in `httpd.conf` |
| `executable not found` | wrong `php.exe` path | fix `php.binaries[].path` |
| `php subprocess timed out` | AV scanning `php.exe` | raise `php.subprocess_timeout` |
| OOM test shows no fatal marker | `memory_limit=-1` or flood too small | raise `tests.oom.fields` / `nesting` |
| `--check` says Manual | `expose_php=Off` | expected; read `php -v` on the host |

---

## Remediation

`--report` embeds this list. Short version:

1. Update PHP to **8.5.12, 8.4.27, 8.3.36 or 8.2.35**, or apply the vendor
   backport. PHP 8.1 and older get no upstream release — minimal source
   backports exist for 7.4, 8.0, 8.1; distros and LTS vendors backport.
2. Restart Apache so workers reload, then re-run `--check`.
3. If patching is delayed, set these in `php.ini` and restart:
   - `memory_limit=-1` (CVE-2026-109618)
   - `session.upload_progress.enabled=0` (CVE-2026-109619)
   - on PHP 8.5 also `fatal_error_backtraces=0`
   - do **not** use `RLIMIT_AS` / `RLIMIT_DATA`
4. Re-run `--local-test` and diff against the baseline report.

**There is no complete configuration mitigation. Patching is the only fix.**

---

## Limitations

- Version classification cannot see vendor backports.
- The OOM test does not prove the use-after-free.
- The leak test is a regex heuristic, not a memory parse.
- Windows builds are ZTS; every published profile is a Linux NTS build.
- The published offsets are for `libphp.so` (ELF); Windows loads
  `php8apache2_4.dll` (PE).
- XAMPP uses `mpm_winnt` (threads), not prefork (processes).

### Requires a separate isolated Linux environment

1. Any **RCE claim**.
2. Layer 3 **memory disclosure** under a controlled config.
3. Offset-dependent stages (only 5 of 13 published profiles have verified RCE).
4. Meaningful **vulnerable vs patched** comparison under identical conditions.
5. The **FPM** session-lifecycle chain (XAMPP gives you mod_php only).

Suggested lab:

```bash
docker run --rm -p 8105:80 php:8.4.26-apache
# then set memory_limit=8M, display_errors=On, session.upload_progress=On, one worker
python php2shell.py --target http://127.0.0.1:8105 --allow-private --local-test
```

---

## Known traps

Three things that bit during development, kept here on purpose:

1. `php2shell.py` in the project root shadows the `php2shell` package in
   `src/`. The shim inserts `src` at `sys.path[0]` and creates
   `__init__.py` if absent.
2. In PowerShell, `.venv\Scripts\activate.bat` is the cmd shim. Use
   `Activate.ps1`.
3. `pytest` and `pip` as bare commands can resolve outside the venv. Use
   `python -m pytest` and `python -m pip`.

---

## Acceptable use

Authorized testing only. A public website is not a laboratory. The chain is
disruptive: it sends large multipart bodies, triggers OOM and can kill Apache
children.

## License

MIT. See `LICENSE`.

## Sources

- php.net advisory: https://www.php.net/archive/2026.php#2026-10-21-5
- GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp
- Wiz: https://www.wiz.io/blog/php2shell-php-rce
- Calif: https://calif.io/php2shell/
- Sansec: https://sansec.io/research/php2shell
- NCSC-NL: https://github.com/NCSC-NL/php2shell