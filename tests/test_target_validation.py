from __future__ import annotations

import pytest

from php2shell.config import load_config
from php2shell.target_validation import TargetError, validate_target


@pytest.fixture()
def cfg(tmp_path):
    c = load_config(path=None, root=tmp_path)
    return c


def test_loopback_allowed(cfg):
    v = validate_target("http://127.0.0.1:8088", cfg)
    assert v.allowed and v.is_loopback


def test_localhost_name_allowed(cfg):
    v = validate_target("http://localhost:8088/", cfg)
    assert v.allowed


def test_ipv6_loopback_allowed(cfg):
    v = validate_target("http://[::1]:8088/", cfg)
    assert v.allowed


def test_public_rejected_by_default(cfg):
    v = validate_target("http://93.184.216.34/", cfg)
    assert not v.allowed


def test_allow_public_switch(cfg):
    cfg.data["targets"]["allow_public"] = True
    v = validate_target("http://93.184.216.34/", cfg)
    assert v.allowed


def test_allowed_hosts_list(cfg):
    cfg.data["targets"]["allowed_hosts"] = ["example.test"]
    v = validate_target("http://example.test/", cfg)
    assert v.allowed


def test_private_cidr(cfg):
    cfg.data["targets"]["allowed_cidrs"] = ["127.0.0.0/8", "10.0.0.0/8"]
    v = validate_target("http://10.0.0.5/", cfg)
    assert v.allowed


def test_bad_scheme(cfg):
    with pytest.raises(TargetError):
        validate_target("ftp://127.0.0.1/", cfg)


def test_no_host(cfg):
    with pytest.raises(TargetError):
        validate_target("http:///path", cfg)