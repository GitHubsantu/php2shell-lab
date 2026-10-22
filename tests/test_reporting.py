from __future__ import annotations

import json

from php2shell.config import load_config
from php2shell.reporting import build_report, redact_headers, write_both


def test_set_cookie_redacted(tmp_path):
    cfg = load_config(path=None, root=tmp_path)
    out = redact_headers({"Set-Cookie": "PHPSESSID=abcdef1234567890; Path=/", "Server": "Apache"}, cfg)
    assert "abcdef1234567890" not in out["Set-Cookie"]
    assert "chars>" in out["Set-Cookie"]
    assert out["Server"] == "Apache"


def test_authorization_truncated(tmp_path):
    cfg = load_config(path=None, root=tmp_path)
    out = redact_headers({"Authorization": "Bearer " + "x" * 100}, cfg)
    assert out["Authorization"].endswith("...")


def test_report_roundtrip(tmp_path):
    cfg = load_config(path=None, root=tmp_path)
    cfg.data["reporting"]["dir"] = str(tmp_path / "reports")
    report = build_report(cfg, mode="full", payload={"verdict": "Potentially affected"})
    jpath, mpath = write_both(cfg, report, stem="t")
    assert json.loads(jpath.read_text(encoding="utf-8"))["mode"] == "full"
    assert "Potentially affected" in mpath.read_text(encoding="utf-8")