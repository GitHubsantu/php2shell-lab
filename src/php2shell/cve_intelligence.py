"""Module A - verified CVE intelligence and verdict logic.

Design rule: a version string is *evidence*, never proof. Distro backports keep
the upstream version number, so classification always carries a limitation note.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

CVE_109618 = "CVE-2026-109618"
CVE_109619 = "CVE-2026-109619"

_VERSION_RE = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?")


class Verdict(str, Enum):
    NOT_ASSESSED = "Not assessed"
    POTENTIALLY_AFFECTED = "Potentially affected"
    NO_EVIDENCE = "No evidence detected"
    FIXED_BUILD = "Fixed build identified"
    MANUAL = "Manual verification required"


class Branch(str, Enum):
    AFFECTED = "affected"
    FIXED = "fixed"
    EOL_UNPATCHED = "eol-unpatched"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class CveRecord:
    id: str
    title: str
    ghsa: str
    cvss_v4: float
    cvss_v3_nvd: float | None
    component: str
    summary: str
    preconditions: tuple[str, ...]
    sapis_confirmed: tuple[str, ...]
    sapis_conditional: tuple[str, ...]
    exploitable: str
    mitigations: tuple[str, ...]
    references: tuple[str, ...]


@dataclass
class Finding:
    verdict: Verdict
    reasons: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "reasons": self.reasons,
            "limitations": self.limitations,
            "evidence": self.evidence,
        }


@dataclass
class CveIntel:
    cves: dict[str, CveRecord]
    fixed_releases: dict[str, str]
    eol_branches: tuple[str, ...]
    earliest_affected: str
    backport_packages: tuple[dict[str, str], ...]
    compiled: str
    confidence_note: str

    @property
    def max_known_branch(self) -> tuple[int, int]:
        keys = [parse_version(v) for v in self.fixed_releases]
        keys = [k for k in keys if k]
        return max((k[0], k[1]) for k in keys) if keys else (8, 5)


def parse_version(text: str | None) -> tuple[int, int, int] | None:
    """Parse a leading MAJOR.MINOR[.PATCH] from a possibly suffixed version."""
    if not text:
        return None
    m = _VERSION_RE.match(str(text).strip())
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


def branch_key(text: str | None) -> tuple[int, int] | None:
    v = parse_version(text)
    return (v[0], v[1]) if v else None


def load_intel(path: Path) -> CveIntel:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    cves: dict[str, CveRecord] = {}
    for entry in raw.get("cves", []):
        rec = CveRecord(
            id=str(entry["id"]),
            title=str(entry["title"]),
            ghsa=str(entry["ghsa"]),
            cvss_v4=float(entry["cvss_v4"]),
            cvss_v3_nvd=float(entry["cvss_v3_nvd"]) if entry.get("cvss_v3_nvd") else None,
            component=str(entry.get("component", "")),
            summary=str(entry.get("summary", "")).strip(),
            preconditions=tuple(entry.get("preconditions", ())),
            sapis_confirmed=tuple(entry.get("sapis_confirmed", ())),
            sapis_conditional=tuple(entry.get("sapis_conditional", ())),
            exploitable=str(entry.get("exploitable", "")).strip(),
            mitigations=tuple(entry.get("mitigations", ())),
            references=tuple(entry.get("references", ())),
        )
        cves[rec.id] = rec

    meta = raw.get("meta", {})
    return CveIntel(
        cves=cves,
        fixed_releases={str(k): str(v) for k, v in (raw.get("fixed_releases") or {}).items()},
        eol_branches=tuple(str(b) for b in raw.get("eol_branches", ())),
        earliest_affected=str(raw.get("earliest_affected", "5.4.0")),
        backport_packages=tuple(raw.get("backport_packages", ())),
        compiled=str(meta.get("compiled", "unknown")),
        confidence_note=str(meta.get("confidence_note", "")).strip(),
    )


def classify_branch(version: str | None, intel: CveIntel) -> tuple[Branch, str]:
    """Classify a version against the fixed releases. Never claims exploitation."""
    parsed = parse_version(version)
    if parsed is None:
        return Branch.UNKNOWN, "no usable version string"

    major_minor = f"{parsed[0]}.{parsed[1]}"
    fixed = intel.fixed_releases.get(major_minor)
    if fixed:
        fixed_parsed = parse_version(fixed)
        if fixed_parsed and parsed >= fixed_parsed:
            return Branch.FIXED, f"{version} >= fixed release {fixed} for branch {major_minor}"
        return (
            Branch.AFFECTED,
            f"{version} is below the fixed release {fixed} for branch {major_minor}",
        )

    if major_minor in intel.eol_branches:
        return (
            Branch.EOL_UNPATCHED,
            f"branch {major_minor} is end-of-life; no upstream release (source backports only)",
        )

    if (parsed[0], parsed[1]) > intel.max_known_branch:
        return Branch.UNKNOWN, f"branch {major_minor} predates this advisory dataset"

    return Branch.UNKNOWN, f"branch {major_minor} not in the verified dataset"


def backport_hint(version: str | None, intel: CveIntel) -> str | None:
    """Detect a vendor package string that indicates a backported fix."""
    if not version:
        return None
    needle = str(version)
    for pkg in intel.backport_packages:
        prefix = pkg.get("version_prefix", "")
        if prefix and prefix in needle:
            return f"matches {pkg.get('distro')} fixed package {pkg.get('package')} {prefix}"
    # Debian/Ubuntu style suffix without an exact table match.
    if re.search(r"ubuntu\d", needle) or re.search(r"deb\d+u\d", needle) or "+esm" in needle:
        return "distro-style package suffix present; check the vendor changelog for the CVE id"
    return None


def evaluate(
    version: str | None,
    *,
    intel: CveIntel,
    reachable: bool,
    sapi: str | None = None,
    ini: dict[str, Any] | None = None,
    source: str = "unknown",
) -> Finding:
    """Produce one of the five verdicts with evidence and explicit limitations."""
    ini = ini or {}
    finding = Finding(verdict=Verdict.NOT_ASSESSED)
    finding.evidence = {
        "version": version,
        "version_source": source,
        "sapi": sapi,
        "reachable": reachable,
        "ini_subset": {
            k: ini.get(k)
            for k in (
                "memory_limit",
                "post_max_size",
                "session.upload_progress.enabled",
                "fatal_error_backtraces",
                "display_errors",
                "expose_php",
            )
            if k in ini
        },
    }

    if not reachable:
        finding.reasons.append("target did not answer an HTTP request")
        finding.limitations.append("nothing can be concluded without a response")
        return finding

    if not version:
        finding.verdict = Verdict.MANUAL
        finding.reasons.append("no version disclosed by headers or probe")
        finding.limitations.append(
            "expose_php may be Off, or the probe is not deployed; read php -v on the host"
        )
        return finding

    branch, reason = classify_branch(version, intel)
    hint = backport_hint(version, intel)

    if branch is Branch.FIXED:
        finding.verdict = Verdict.FIXED_BUILD
        finding.reasons.append(reason)
    elif branch in (Branch.AFFECTED, Branch.EOL_UNPATCHED):
        if hint:
            finding.verdict = Verdict.MANUAL
            finding.reasons.append(reason)
            finding.reasons.append(f"possible vendor backport: {hint}")
            finding.limitations.append(
                "a vendor backport keeps the upstream version number, so the version "
                "alone cannot separate patched from unpatched"
            )
        else:
            finding.verdict = Verdict.POTENTIALLY_AFFECTED
            finding.reasons.append(reason)
            finding.limitations.append(
                "affected range does not mean exploitable: the published chains need "
                "per-build offsets, a low memory_limit and display_errors=On"
            )
    else:
        finding.verdict = Verdict.NO_EVIDENCE
        finding.reasons.append(reason)

    # SAPI gating.
    if sapi:
        lowered = sapi.lower()
        if "apache" in lowered or "mod_php" in lowered:
            finding.reasons.append("SAPI is mod_php: highest-risk and the only confirmed pre-auth path")
        elif "fpm" in lowered:
            finding.reasons.append("SAPI is FPM: conditional exposure, application-dependent")
        else:
            finding.reasons.append(f"SAPI {sapi}: exposure is not established by the advisories")

    # Config preconditions.
    upload = str(ini.get("session.upload_progress.enabled", "")).lower()
    if upload in ("0", "off", "false", ""):
        finding.reasons.append("session.upload_progress is disabled: the 109619 session path is mitigated")
    limit = str(ini.get("memory_limit", ""))
    if limit in ("-1", ""):
        finding.reasons.append("memory_limit is unlimited: the 109618 OOM path is mitigated")
    if str(ini.get("display_errors", "")).lower() in ("0", "off", "false"):
        finding.limitations.append("display_errors is Off: the shipped stage-1 leak is not expected to fire")

    finding.limitations.append("classification is version-based evidence, not proof of exploitation")
    return finding