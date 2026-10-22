"""Command line interface and interactive menu."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import FRAMEWORK_NAME, MODULE_STATUS, SUPPORTED_MODULES, __version__
from .config import ConfigError, load_config
from .cve_intelligence import (
    CVE_109618,
    CVE_109619,
    Verdict,
    evaluate,
    load_intel,
)
from .fingerprint import deploy_probe, fingerprint_cli, fingerprint_web
from .logging_config import setup_logging
from .race_diagnostics import run_race
from .reporting import build_report, redact_headers, write_both
from .safe_tests import run_all
from .scanner import recon, scan
from .target_validation import TargetError, validate_target

console = Console()
PROBE = "p2s-local-lab-token"

EPILOG = """\
examples:
  python php2shell.py --target http://127.0.0.1:8088 --scan
  python php2shell.py --target http://127.0.0.1:8088 --check
  python php2shell.py --target http://127.0.0.1:8088 --recon
  python php2shell.py --local-test --oom --leak
  python php2shell.py --local-test --report
  python php2shell.py --race --concurrency 16
  python php2shell.py --menu

safety:
  loopback only by default; --allow-public to widen
  redirects are not followed outside the lab
  no exploit is launched silently; every subprocess is logged
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="php2shell.py",
        description=f"{FRAMEWORK_NAME} v{__version__} - local lab research only",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="store_true", help="show version and modules")
    p.add_argument("--target", default=None, help="target URL (default from config)")
    p.add_argument("--scan", action="store_true", help="reachability and runtime indicators")
    p.add_argument("--check", action="store_true", help="evidence-based verdict")
    p.add_argument("--recon", action="store_true", help="headers, status, timing")
    p.add_argument("--local-test", action="store_true", dest="local_test",
                   help="run the local safe test suite")
    p.add_argument("--race", action="store_true", help="concurrency diagnostics")
    p.add_argument("--report", action="store_true", help="write JSON and Markdown reports")
    p.add_argument("--menu", action="store_true", help="interactive menu")
    p.add_argument("--config", type=Path, default=None, help="path to config YAML")
    p.add_argument("--php-bin", default=None, help="php.binaries name to use")
    p.add_argument("--deploy-probe", action="store_true", help="copy the probe into the webroot")
    p.add_argument("--no-probe", action="store_true", help="skip all probe usage")
    p.add_argument("--oom", action="store_true", help="include the OOM test")
    p.add_argument("--leak", action="store_true", help="include the leak heuristic")
    p.add_argument("--deep", action="store_true", help="invoke an external PoC if configured")
    p.add_argument("--poc", default=None, help="path to an external PoC script")
    p.add_argument("--concurrency", type=int, default=None)
    p.add_argument("--requests", type=int, default=None, dest="requests_per_worker")
    p.add_argument("--timeout", type=float, default=None)
    p.add_argument("--allow-public", action="store_true")
    p.add_argument("--json", action="store_true", dest="json_out", help="emit JSON only")
    p.add_argument("--quiet", action="store_true")
    return p


def _banner(cfg) -> None:
    console.print(Panel.fit(
        f"[bold]{FRAMEWORK_NAME}[/bold]  v{__version__}\n"
        f"CVE-2026-109618 / CVE-2026-109619  -  lab only\n"
        f"target [cyan]{cfg.target}[/cyan]   config [dim]{cfg.source or 'defaults'}[/dim]",
        border_style="cyan",
    ))


def _status_label(key: str) -> str:
    mapping = {
        "implemented": "[green]implemented[/green]",
        "experimental": "[yellow]experimental[/yellow]",
        "unsupported": "[red]unsupported[/red]",
    }
    return mapping.get(MODULE_STATUS.get(key, "unsupported"), "[red]unsupported[/red]")


def cmd_version() -> int:
    console.print(f"{FRAMEWORK_NAME} v{__version__}")
    table = Table(title="research modules", show_header=True, header_style="bold")
    table.add_column("module")
    table.add_column("description")
    for key, desc in SUPPORTED_MODULES:
        table.add_row(key, desc)
    console.print(table)
    console.print("\ncapabilities and maturity:")
    for name, status in MODULE_STATUS.items():
        console.print(f"  {name:22} {_status_label(name)}")
    return 0


def cmd_scan(cfg, target: str, json_out: bool) -> dict:
    result = scan(target, cfg)
    if json_out:
        return result
    _banner(cfg)
    v = result["validation"]
    console.print(f"target: {v['url']}  allowed={v['allowed']}  ({v['reason']})")
    obs = result.get("observation")
    if obs:
        console.print(f"HTTP {obs['status']}  in {obs['elapsed_ms']} ms")
        for line in obs["indicators"]:
            console.print(f"  - {line}")
    for note in result["notes"]:
        console.print(f"[dim]{note}[/dim]")
    return result


def cmd_recon(cfg, target: str, json_out: bool) -> dict:
    result = recon(target, cfg)
    if json_out:
        return result
    _banner(cfg)
    table = Table(title="recon", show_header=True, header_style="bold")
    table.add_column("path")
    table.add_column("status")
    table.add_column("ms")
    table.add_column("server")
    for probe in result["probes"]:
        table.add_row(
            probe["url"].split("//", 1)[-1],
            str(probe.get("status")),
            str(probe.get("elapsed_ms")),
            probe["headers"].get("server", "-"),
        )
    console.print(table)
    for note in result["notes"]:
        console.print(f"[dim]{note}[/dim]")
    return result


def cmd_check(cfg, target: str, json_out: bool, deploy: bool) -> dict:
    validation = validate_target(target, cfg)
    payload: dict = {"validation": validation.as_dict()}

    cli_fp = None
    if not json_out:
        _banner(cfg)
    console.print(f"target: {validation.url}  allowed={validation.allowed}")

    if not validation.allowed:
        payload["verdict"] = Verdict.NOT_ASSESSED.value
        console.print(f"[red]rejected:[/red] {validation.reason}")
        return payload

    if deploy:
        ok, msg = deploy_probe(cfg)
        console.print(f"probe: {msg}" if ok else f"[red]probe: {msg}[/red]")

    reachable = False
    try:
        import requests
        reachable = requests.get(target, timeout=cfg.request_timeout,
                                 allow_redirects=False).status_code < 600
    except Exception:  # noqa: BLE001
        reachable = False

    web = None
    if cfg.probe_enabled:
        web = fingerprint_web(target, cfg)
        if web.ok:
            payload["environment"] = {
                "web_sapi": web.sapi,
                "php_version": web.version,
                "pid": web.data.get("pid"),
                "zts": web.data.get("zts"),
                "arch": web.data.get("arch"),
                "ini": web.ini,
            }

    binary = cfg.php_binary(None)
    if binary:
        cli_fp = fingerprint_cli(binary)
        payload.setdefault("environment", {})["cli"] = cli_fp.as_dict()

    version = (web.version if web and web.ok else None) or (cli_fp.version if cli_fp else None)
    source = "web probe" if (web and web.ok) else ("php -v" if cli_fp and cli_fp.version else "none")
    sapi = (web.sapi if web and web.ok else None) or (cli_fp.sapi if cli_fp else None)

    intel = load_intel(cfg.root / "config" / "cve_intelligence.yaml")
    finding = evaluate(
        version, intel=intel, reachable=reachable, sapi=sapi,
        ini=(web.ini if web and web.ok else (cli_fp.ini if cli_fp else {})),
        source=source,
    )
    payload["finding"] = finding.as_dict()
    payload["verdict"] = finding.verdict.value

    if not json_out:
        colour = {
            Verdict.NOT_ASSESSED: "white",
            Verdict.POTENTIALLY_AFFECTED: "yellow",
            Verdict.NO_EVIDENCE: "blue",
            Verdict.FIXED_BUILD: "green",
            Verdict.MANUAL: "magenta",
        }[finding.verdict]
        console.print(Panel.fit(f"[bold {colour}]{finding.verdict.value}[/bold {colour}]",
                                title="verdict"))
        console.print(f"version={version}  source={source}  sapi={sapi}")
        for r in finding.reasons:
            console.print(f"  - {r}")
        console.print("[dim]limitations:[/dim]")
        for l in finding.limitations:  # noqa: E741
            console.print(f"[dim]  - {l}[/dim]")
        console.print("[dim]affected range is not proof of exploitation.[/dim]")
    return payload


def cmd_local_test(cfg, target: str, args, json_out: bool) -> dict:
    payload: dict = {}
    binary = cfg.php_binary(args.php_bin)
    if binary:
        fp = fingerprint_cli(binary)
        payload["cli_binary"] = fp.as_dict()
        if not json_out:
            _banner(cfg)
            console.print(f"php binary: {fp.path}  exists={fp.exists}")
            console.print(f"version={fp.version}  sapi={fp.sapi}  zts={fp.zts}")
            if fp.loaded_ini:
                console.print(f"loaded ini: {fp.loaded_ini}")
            if fp.error:
                console.print(f"[red]{fp.error}[/red]")

    if args.deploy_probe:
        ok, msg = deploy_probe(cfg, force=True)
        console.print(f"probe: {msg}")

    results = run_all(target, cfg, include_oom=args.oom, include_leak=args.leak)
    payload["tests"] = [r.as_dict() for r in results]

    if args.deep:
        from .deep_mode import run_poc
        payload["deep_mode"] = run_poc(target, cfg, args.poc).as_dict()

    if not json_out:
        table = Table(title="safe tests", show_header=True, header_style="bold")
        for col in ("test", "layer", "ran", "result", "actual"):
            table.add_column(col)
        for r in results:
            mark = {True: "[green]pass[/green]", False: "[red]fail[/red]", None: "n/a"}[r.passed]
            table.add_row(r.name, str(r.layer), str(r.ran), mark, r.actual[:60])
        console.print(table)
        for r in results:
            for note in r.notes:
                console.print(f"[dim]  {r.name}: {note}[/dim]")
    return payload


def cmd_race(cfg, target: str, args, json_out: bool) -> dict:
    report = run_race(target, cfg, args.concurrency, args.requests_per_worker)
    payload = report.as_dict()
    if not json_out:
        _banner(cfg)
        table = Table(title="race diagnostics", show_header=True)
        table.add_column("metric")
        table.add_column("value")
        for key, value in payload.items():
            if key == "notes":
                continue
            table.add_row(str(key), str(value))
        console.print(table)
        for note in report.notes:
            console.print(f"[dim]{note}[/dim]")
    return payload


def cmd_report(cfg, target: str, args) -> int:
    _banner(cfg)
    payload: dict = {}
    payload["check"] = cmd_check(cfg, target, json_out=False, deploy=args.deploy_probe)
    payload["tests"] = [r.as_dict() for r in run_all(
        target, cfg, include_oom=args.oom, include_leak=args.leak)]
    payload["race"] = run_race(target, cfg, args.concurrency, args.requests_per_worker).as_dict()

    intel = load_intel(cfg.root / "config" / "cve_intelligence.yaml")
    remediation = [
        "Update PHP to 8.5.12, 8.4.27, 8.3.36 or 8.2.35, or apply the vendor backport.",
        "Restart Apache so workers reload the new code, then re-run --check.",
        "If patching is delayed: set memory_limit=-1 and session.upload_progress.enabled=0 "
        "in php.ini, restart, and do not use RLIMIT_AS / RLIMIT_DATA.",
        "On PHP 8.5 also set fatal_error_backtraces=0.",
        "Re-run --local-test and compare against this baseline report.",
    ]
    payload["remediation"] = remediation
    payload["cve_intel_compiled"] = intel.compiled

    report = build_report(cfg, mode="full", payload=payload)
    jpath, mpath = write_both(cfg, report, stem="full")
    console.print(f"JSON: {jpath}")
    console.print(f"Markdown: {mpath}")
    return 0


def cmd_intel(cfg) -> int:
    intel = load_intel(cfg.root / "config" / "cve_intelligence.yaml")
    console.print(f"[bold]CVE intelligence[/bold] (compiled {intel.compiled})")
    for cve_id, rec in intel.cves.items():
        console.print(Panel.fit(
            f"[bold]{rec.id}[/bold] - {rec.title}\n"
            f"CVSS v4.0 {rec.cvss_v4}   {rec.ghsa}\n"
            f"{rec.summary[:400]}\n\n"
            f"confirmed SAPIs: {', '.join(rec.sapis_confirmed)}\n"
            f"exploitable: {rec.exploitable}",
            title=cve_id, border_style="cyan"))
    console.print("fixed releases: " + ", ".join(f"{k}->{v}" for k, v in intel.fixed_releases.items()))
    console.print("[dim]" + intel.confidence_note + "[/dim]")
    return 0


MENU = [
    ("1", "Scan", "reachability, headers, runtime indicators", "scan"),
    ("2", "Check", "evidence vs verified advisory -> verdict", "check"),
    ("3", "Recon", "headers, status codes, response timing", "recon"),
    ("4", "Local test", "baseline + probe + OOM + leak", "local_test"),
    ("5", "Race diagnostics", "concurrency, latency, worker churn", "race"),
    ("6", "Report", "timestamped JSON + Markdown", "report"),
    ("7", "CVE intelligence", "advisories, affected/fixed, mitigations", "intel"),
    ("8", "Help / version", "modules and maturity", "version"),
    ("0", "Exit", "", "exit"),
]


def menu(cfg, args) -> int:
    while True:
        _banner(cfg)
        table = Table(show_header=False, box=None)
        for key, name, desc, _ in MENU:
            table.add_row(f"[cyan]{key}[/cyan]", f"[bold]{name}[/bold]", f"[dim]{desc}[/dim]")
        console.print(table)
        console.print("[dim]Ctrl+C cancels a running task[/dim]")
        try:
            choice = console.input("[bold]> [/bold]").strip()
        except (EOFError, KeyboardInterrupt):
            console.print()
            return 0

        mapping = {k: action for k, _, _, action in MENU}
        action = mapping.get(choice)
        if action == "exit":
            return 0
        if action is None:
            continue
        try:
            dispatch(action, cfg, args)
        except KeyboardInterrupt:
            console.print("[yellow]cancelled[/yellow]")


def dispatch(action: str, cfg, args) -> int:
    target = args.target or cfg.target
    if action == "version":
        return cmd_version()
    if action == "intel":
        return cmd_intel(cfg)
    if action == "scan":
        cmd_scan(cfg, target, args.json_out)
    elif action == "check":
        cmd_check(cfg, target, args.json_out, args.deploy_probe)
    elif action == "recon":
        cmd_recon(cfg, target, args.json_out)
    elif action == "local_test":
        cmd_local_test(cfg, target, args, args.json_out)
    elif action == "race":
        cmd_race(cfg, target, args, args.json_out)
    elif action == "report":
        cmd_report(cfg, target, args)
    return 0

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        return cmd_version()

    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        console.print(f"[red]config error:[/red] {exc}")
        return 2

    if args.allow_public:
        cfg.data["targets"]["allow_public"] = True
    if args.timeout:
        cfg.data["targets"]["request_timeout"] = args.timeout
    if args.no_probe:
        cfg.data["probe"]["enabled"] = False
    if args.target:
        cfg.data["targets"]["default"] = args.target

    setup_logging(
        cfg.log_dir(),
        str(cfg.data["logging"]["level"]),
        int(cfg.data["logging"]["max_bytes"]),
        int(cfg.data["logging"]["backup_count"]),
    )

    actions = (args.scan, args.check, args.recon, args.local_test, args.race, args.report)

    try:
        # No explicit action, or --menu explicitly: go interactive.
        if args.menu or not any(actions):
            return menu(cfg, args)

        action = (
            "report" if args.report else
            "local_test" if args.local_test else
            "race" if args.race else
            "check" if args.check else
            "recon" if args.recon else "scan"
        )
        return dispatch(action, cfg, args)
    except TargetError as exc:
        console.print(f"[red]target error:[/red] {exc}")
        return 3
    except KeyboardInterrupt:
        console.print("\n[yellow]interrupted[/yellow]")
        return 130


if __name__ == "__main__":
    sys.exit(main())