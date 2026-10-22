from __future__ import annotations

from pathlib import Path

from php2shell.cve_intelligence import (
    Branch,
    Verdict,
    backport_hint,
    classify_branch,
    evaluate,
    load_intel,
    parse_version,
)

INTEL_PATH = Path(__file__).resolve().parents[1] / "config" / "cve_intelligence.yaml"


def intel():
    return load_intel(INTEL_PATH)


def test_parse_version_plain():
    assert parse_version("8.2.12") == (8, 2, 12)


def test_parse_version_with_distro_suffix():
    assert parse_version("8.1.2-1ubuntu2.28") == (8, 1, 2)


def test_parse_version_none():
    assert parse_version(None) is None
    assert parse_version("not-a-version") is None


def test_affected_branch():
    branch, reason = classify_branch("8.2.12", intel())
    assert branch is Branch.AFFECTED
    assert "8.2.35" in reason


def test_fixed_branch():
    branch, _ = classify_branch("8.2.35", intel())
    assert branch is Branch.FIXED


def test_newer_than_fixed():
    branch, _ = classify_branch("8.5.12", intel())
    assert branch is Branch.FIXED


def test_eol_branch():
    branch, reason = classify_branch("7.4.33", intel())
    assert branch is Branch.EOL_UNPATCHED
    assert "end-of-life" in reason


def test_backport_hint_detects_ubuntu():
    assert backport_hint("8.1.2-1ubuntu2.28", intel())


def test_backport_hint_none_for_plain():
    assert backport_hint("8.2.12", intel()) is None


def test_evaluate_unreachable():
    f = evaluate(None, intel=intel(), reachable=False)
    assert f.verdict is Verdict.NOT_ASSESSED


def test_evaluate_no_version_is_manual():
    f = evaluate(None, intel=intel(), reachable=True)
    assert f.verdict is Verdict.MANUAL


def test_evaluate_fixed_build():
    f = evaluate("8.3.36", intel=intel(), reachable=True, sapi="apache2handler")
    assert f.verdict is Verdict.FIXED_BUILD


def test_evaluate_affected_is_not_confirmation():
    f = evaluate("8.2.12", intel=intel(), reachable=True, sapi="apache2handler")
    assert f.verdict is Verdict.POTENTIALLY_AFFECTED
    assert any("not mean exploitable" in x for x in f.limitations)


def test_evaluate_backport_version_is_manual():
    f = evaluate("8.1.2-1ubuntu2.28", intel=intel(), reachable=True)
    assert f.verdict is Verdict.MANUAL


def test_mitigation_notes_present():
    f = evaluate("8.2.12", intel=intel(), reachable=True,
                 ini={"session.upload_progress.enabled": "0", "memory_limit": "-1"})
    assert any("upload_progress" in r for r in f.reasons)
    assert any("memory_limit" in r for r in f.reasons)