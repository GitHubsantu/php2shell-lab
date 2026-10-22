"""Lab-only target admission control.

Default allow-list: loopback only. Anything else must be explicitly enabled
via config, so the tool cannot accidentally scan the public internet.
Redirects are not followed outside the lab.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .config import AppConfig

LOOPBACK_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost"}
_LOOPBACK_NETS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
)


class TargetError(ValueError):
    """Raised for malformed or inadmissible targets."""


@dataclass(frozen=True)
class TargetValidation:
    url: str
    host: str
    port: int | None
    scheme: str
    allowed: bool
    reason: str
    is_loopback: bool
    is_private: bool
    resolved: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict:
        return {
            "url": self.url,
            "host": self.host,
            "port": self.port,
            "scheme": self.scheme,
            "allowed": self.allowed,
            "reason": self.reason,
            "is_loopback": self.is_loopback,
            "is_private": self.is_private,
            "resolved": list(self.resolved),
        }


def _is_loopback_ip(ip: ipaddress._BaseAddress) -> bool:
    return any(ip in net for net in _LOOPBACK_NETS) or ip.is_loopback


def _resolve(host: str) -> tuple[str, ...]:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return ()
    seen: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in seen:
            seen.append(addr)
    return tuple(seen)


def validate_target(url: str, cfg: AppConfig) -> TargetValidation:
    """Decide whether a URL may be contacted.

    Never raises for an unreachable host; only for a malformed URL.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise TargetError(f"unsupported scheme {parsed.scheme!r} in {url!r}")
    if not parsed.hostname:
        raise TargetError(f"no host in {url!r}")

    host = parsed.hostname.lower()
    tcfg = cfg.data["targets"]

    # Explicit host allow-list wins over everything.
    if host in {str(h).lower() for h in tcfg.get("allowed_hosts", [])}:
        return TargetValidation(url, host, parsed.port, parsed.scheme, True,
                                "listed in targets.allowed_hosts", False, False, ())

    resolved = _resolve(host)
    ips: list[ipaddress._BaseAddress] = []
    for addr in resolved:
        try:
            ips.append(ipaddress.ip_address(addr))
        except ValueError:  # pragma: no cover
            continue

    loopback = host in LOOPBACK_NAMES or any(_is_loopback_ip(ip) for ip in ips)
    if loopback:
        return TargetValidation(url, host, parsed.port, parsed.scheme, True,
                                "loopback destination", True, False, resolved)

    private = bool(ips) and all(ip.is_private for ip in ips)
    for cidr in tcfg.get("allowed_cidrs", []):
        try:
            net = ipaddress.ip_network(str(cidr), strict=False)
        except ValueError:
            continue
        if any(ip in net for ip in ips):
            return TargetValidation(url, host, parsed.port, parsed.scheme, True,
                                    f"within allowed_cidrs {cidr}", False, private, resolved)

    if private and tcfg.get("allow_private"):
        return TargetValidation(url, host, parsed.port, parsed.scheme, True,
                                "private address and targets.allow_private is set",
                                False, True, resolved)

    if tcfg.get("allow_public"):
        return TargetValidation(url, host, parsed.port, parsed.scheme, True,
                                "targets.allow_public is set", False, private, resolved)

    detail = ", ".join(resolved) if resolved else "unresolved"
    return TargetValidation(url, host, parsed.port, parsed.scheme, False,
                            f"not loopback and not allow-listed (resolved: {detail})",
                            False, private, resolved)


def redirect_allowed(origin: str, location: str, cfg: AppConfig) -> tuple[bool, str]:
    """Decide whether a redirect target is still inside the lab."""
    try:
        check = validate_target(location, cfg)
    except TargetError as exc:
        return False, f"malformed redirect target: {exc}"
    if not check.allowed:
        return False, f"redirect leaves the lab: {check.reason}"
    if not cfg.data["targets"].get("follow_redirects_within_lab", False):
        return False, "redirects not followed (targets.follow_redirects_within_lab=false)"
    origin_host = (urlparse(origin).hostname or "").lower()
    if check.host != origin_host:
        return False, f"cross-host redirect {origin_host} -> {check.host}"
    return True, "redirect within lab"