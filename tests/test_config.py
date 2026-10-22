from __future__ import annotations

import pytest

from php2shell.config import ConfigError, load_config


def test_defaults_load(tmp_path):
    cfg = load_config(path=None, root=tmp_path)
    assert cfg.target.startswith("http://127.0.0.1")


def test_override(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("targets:\n  default: http://127.0.0.1:9999\n", encoding="utf-8")
    cfg = load_config(path=p, root=tmp_path)
    assert cfg.target.endswith("9999")
    assert cfg.data["php"]["binaries"]  # defaults preserved


def test_missing_file_raises(tmp_path):
    with pytest.raises(ConfigError):
        load_config(path=tmp_path / "nope.yaml", root=tmp_path)


def test_bad_yaml(tmp_path):
    p = tmp_path / "b.yaml"
    p.write_text("targets: [1, 2, 3\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path=p, root=tmp_path)


def test_php_binary_lookup(tmp_path):
    cfg = load_config(path=None, root=tmp_path)
    assert cfg.php_binary("xampp") is not None
    assert cfg.php_binary("missing") is None

def test_targets_as_list_raises(tmp_path):
    p = tmp_path / "b.yaml"
    p.write_text("targets: [1,2,3]\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path=p, root=tmp_path)
