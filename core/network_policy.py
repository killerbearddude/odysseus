"""
Network destination policy helpers for Odysseus.

This module contains small, side-effect-free checks used before untrusted fetches
or tool-driven network operations. It deliberately avoids DNS resolution so tests
and policy checks do not create network traffic while deciding whether a URL is
safe to attempt.
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from typing import Iterable
from urllib.parse import urlparse


class NetworkPolicyError(ValueError):
    """Raised when a network destination violates Odysseus network policy."""


@dataclass(frozen=True)
class NetworkTarget:
    """
    Normalized URL destination metadata returned by network-policy checks.

    The object intentionally contains only parsed destination metadata. It does
    not perform DNS resolution or open sockets.
    """

    url: str
    scheme: str
    host: str
    port: int | None


# Private, loopback, link-local, unique-local, and metadata destinations are not
# safe for untrusted content/tool fetches. Blocking these by default prevents SSRF
# against local services, cloud metadata endpoints, and operator LAN resources.
DENIED_IP_NETWORKS = tuple(
    ip_network(network)
    for network in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)

# Hostname-only metadata endpoints must be denied even though policy code does
# not resolve DNS. These names are commonly used by cloud providers.
DENIED_HOSTNAMES = {
    "localhost",
    "metadata",
    "metadata.google.internal",
    "metadata.google.internal.",
    "instance-data",
}

CDN_REFERENCE_PATTERNS = (
    "https://cdn",
    "http://cdn",
    "jsdelivr",
    "unpkg",
    "cdnjs",
    "googleapis",
    "gstatic",
)


def normalize_hostname(host: str) -> str:
    """
    Normalize a URL hostname for policy comparison.

    Args:
        host: Hostname from a parsed URL.

    Returns:
        Lowercase hostname without surrounding IPv6 brackets or a trailing dot.
    """
    return host.strip().strip("[]").lower().rstrip(".")


def parse_network_target(url: str) -> NetworkTarget:
    """
    Parse a URL into destination metadata without performing network access.

    Args:
        url: Candidate URL for an untrusted fetch or external integration.

    Returns:
        Normalized destination metadata.

    Raises:
        NetworkPolicyError: If the URL is malformed or lacks a hostname.
    """
    parsed = urlparse(str(url))
    if not parsed.scheme or not parsed.netloc:
        raise NetworkPolicyError("network URL must include a scheme and host")
    if not parsed.hostname:
        raise NetworkPolicyError("network URL must include a hostname")
    if parsed.username or parsed.password:
        raise NetworkPolicyError("network URL credentials are not allowed")
    return NetworkTarget(
        url=str(url),
        scheme=parsed.scheme.lower(),
        host=normalize_hostname(parsed.hostname),
        port=parsed.port,
    )


def is_denied_hostname(host: str) -> bool:
    """
    Return whether a hostname is directly denied without DNS resolution.

    Args:
        host: URL hostname.

    Returns:
        True when the hostname itself is forbidden for untrusted fetches.
    """
    normalized = normalize_hostname(host)
    return (
        normalized in DENIED_HOSTNAMES
        or normalized.endswith(".localhost")
        or normalized.endswith(".local")
        or normalized.endswith(".internal")
    )


def is_denied_ip_literal(host: str) -> bool:
    """
    Return whether a hostname is an IP literal inside a denied network range.

    Args:
        host: URL hostname that may be an IPv4 or IPv6 literal.

    Returns:
        True when ``host`` is an IP literal in a private, loopback, link-local,
        unique-local, metadata, multicast, or otherwise unsafe range.
    """
    normalized = normalize_hostname(host)
    try:
        address = ip_address(normalized)
    except ValueError:
        return False
    return any(address in network for network in DENIED_IP_NETWORKS)


def validate_untrusted_url(url: str, *, allow_internal: bool = False) -> NetworkTarget:
    """
    Validate a URL before an untrusted fetch or tool-driven network request.

    Args:
        url: Candidate URL.
        allow_internal: Explicit override for trusted administrative call sites.
            The default is fail-closed for private and metadata destinations.

    Returns:
        Normalized network target metadata.

    Raises:
        NetworkPolicyError: If the URL uses an unsupported scheme or targets a
            denied hostname/IP range.
    """
    target = parse_network_target(url)
    if target.scheme not in {"http", "https"}:
        raise NetworkPolicyError(f"network URL scheme '{target.scheme}' is not allowed")

    if not allow_internal and (is_denied_hostname(target.host) or is_denied_ip_literal(target.host)):
        raise NetworkPolicyError("network destination is blocked by Odysseus network policy")

    return target


def find_external_asset_references(text: str) -> list[str]:
    """
    Return CDN/external asset markers found in static text.

    Args:
        text: Static file, template, or documentation content.

    Returns:
        Matching marker strings. This is a scanner helper, not an HTML parser.
    """
    lowered = text.lower()
    return [pattern for pattern in CDN_REFERENCE_PATTERNS if pattern in lowered]


def scan_files_for_external_assets(paths: Iterable[Path]) -> dict[str, list[str]]:
    """
    Scan files for CDN/external asset markers without failing on unreadable files.

    Args:
        paths: Files to inspect.

    Returns:
        Mapping of path string to matched external asset markers.
    """
    findings: dict[str, list[str]] = {}
    for path in paths:
        try:
            matches = find_external_asset_references(path.read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            continue
        if matches:
            findings[str(path)] = matches
    return findings
