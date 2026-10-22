"""PHP2Shell local research framework.

Scope: authorized testing against a local lab only. No reverse shells, no
persistence, no third-party infrastructure, no exploit chaining.
"""
from __future__ import annotations

__version__ = "0.1.0"
FRAMEWORK_NAME = "PHP2Shell Local Research Framework"

SUPPORTED_MODULES: tuple[tuple[str, str], ...] = (
    ("A", "CVE intelligence (verified advisory data)"),
    ("B", "Runtime fingerprinting (CLI + web SAPI)"),
    ("C", "Safe vulnerability validation"),
    ("D", "Race / concurrency diagnostics"),
    ("E", "Remediation verification"),
)

# Module maturity labels rendered in the menu and in every report.
STATUS_IMPLEMENTED = "implemented"
STATUS_EXPERIMENTAL = "experimental"
STATUS_UNSUPPORTED = "unsupported"

MODULE_STATUS: dict[str, str] = {
    "scan": STATUS_IMPLEMENTED,
    "check": STATUS_IMPLEMENTED,
    "recon": STATUS_IMPLEMENTED,
    "local_test": STATUS_IMPLEMENTED,
    "race": STATUS_IMPLEMENTED,
    "report": STATUS_IMPLEMENTED,
    "oom_diagnostic": STATUS_IMPLEMENTED,
    "worker_reuse": STATUS_IMPLEMENTED,
    "leak_inspection": STATUS_EXPERIMENTAL,
    "deep_mode": STATUS_EXPERIMENTAL,
    "full_rce_windows": STATUS_UNSUPPORTED,
    "full_rce_linux": STATUS_EXPERIMENTAL,
}