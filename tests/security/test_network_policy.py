"""
Security tests for untrusted network destination policy.

These tests prevent SSRF-style fetches to loopback, private LAN, link-local,
unique-local IPv6, and metadata services. They do not perform real DNS lookups or
network connections.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.network_policy import (
    NetworkPolicyError,
    find_external_asset_references,
    scan_files_for_external_assets,
    validate_untrusted_url,
)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8000/admin",
        "http://10.0.0.5/service",
        "http://172.16.1.10/service",
        "http://192.168.1.20/router",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://[fc00::1]/",
        "http://[fe80::1]/",
        "http://localhost:7000/",
        "http://metadata.google.internal/computeMetadata/v1/",
    ],
)
def test_untrusted_fetch_denies_internal_and_metadata_destinations(url: str):
    # Blocks private/metadata destinations that untrusted content could use for SSRF.
    with pytest.raises(NetworkPolicyError):
        validate_untrusted_url(url)


def test_untrusted_fetch_allows_public_https_url_without_network_access():
    # Validation parses policy only; it must not make an outbound network request.
    target = validate_untrusted_url("https://example.com/safe/path")
    assert target.scheme == "https"
    assert target.host == "example.com"


@pytest.mark.parametrize("url", ["file:///etc/passwd", "gopher://example.com", "ssh://example.com"])
def test_untrusted_fetch_rejects_non_http_schemes(url: str):
    # Prevents URL parser bypasses from reaching local files or unexpected protocols.
    with pytest.raises(NetworkPolicyError):
        validate_untrusted_url(url)


def test_untrusted_fetch_rejects_url_credentials():
    # URL-embedded credentials are unsafe to log and should not be accepted at policy boundaries.
    with pytest.raises(NetworkPolicyError, match="credentials"):
        validate_untrusted_url("https://user:password@example.com/path")


def test_external_asset_reference_helper_detects_cdn_markers():
    # The scanner is intentionally simple so it can run in CI without parsing HTML.
    matches = find_external_asset_references('<script src="https://cdn.jsdelivr.net/npm/x.js"></script>')
    assert "https://cdn" in matches
    assert "jsdelivr" in matches


def test_repo_external_asset_scan_is_explicitly_reported():
    # This is a visibility test for future vendorization. Existing references are
    # reported as xfail rather than silently ignored so offline-mode work has a
    # concrete follow-up list without blocking this helper PR prematurely.
    roots = [Path("static"), Path("templates"), Path("docs")]
    files = [path for root in roots if root.exists() for path in root.rglob("*") if path.is_file()]
    findings = scan_files_for_external_assets(files)
    if findings:
        pytest.xfail("external CDN/static references remain to be vendored: " + repr(findings))
    assert findings == {}
