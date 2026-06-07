"""
Redaction helpers for Odysseus security audit events.

This module owns the near-term redaction contract used by tool-audit storage.
It deliberately stores hashes, counts, bounded excerpts, and detected secret
classes instead of raw prompts, documents, email bodies, keys, or logs. The
helpers are dependency-free so policy, path-safety, and future diagnostic code
can call them without creating import cycles.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

# Metadata keys with these fragments are treated as sensitive even when the
# value does not look like a known token pattern. This prevents low-entropy test
# passwords, session identifiers, and cookie values from being stored verbatim.
SENSITIVE_METADATA_KEY_FRAGMENTS = (
    "api_key",
    "apikey",
    "app_key",
    "authorization",
    "bearer",
    "cookie",
    "password",
    "secret",
    "session",
    "token",
)


def _is_sensitive_metadata_key(key: object) -> bool:
    """
    Return True when a metadata key implies the paired value is sensitive.

    Pattern-based secret detection misses values such as ``hunter2`` because
    they are short and do not resemble a provider token. Audit metadata is
    key/value structured data, so key names must participate in redaction.
    """
    normalized = str(key).lower().replace("-", "_")
    return any(fragment in normalized for fragment in SENSITIVE_METADATA_KEY_FRAGMENTS)


def redact_metadata_value(value: Any, *, parent_key: object | None = None) -> Any:
    """
    Recursively redact metadata before it is persisted to audit storage.

    Args:
        value: JSON-like metadata value supplied by a caller.
        parent_key: Key associated with ``value`` when traversing mappings.

    Returns:
        A JSON-serializable value with sensitive scalar values replaced.
    """
    if _is_sensitive_metadata_key(parent_key):
        return "[REDACTED]"

    if isinstance(value, dict):
        return {str(key): redact_metadata_value(child, parent_key=key) for key, child in value.items()}

    if isinstance(value, (list, tuple, set)):
        return [redact_metadata_value(child, parent_key=parent_key) for child in value]

    if isinstance(value, str):
        return redact_secret_like_values(value)

    return value



# Broad patterns are used for audit safety. They intentionally favor false
# positives over false negatives because audit logs are persistent records.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "ssh_private_key",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.IGNORECASE,
        ),
    ),
    (
        "gpg_private_key",
        re.compile(
            r"-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----",
            re.IGNORECASE,
        ),
    ),
    (
        "provider_api_key",
        re.compile(r"\b(?:sk|pk|rk|or|ghp|github_pat)_[A-Za-z0-9_\-]{16,}\b"),
    ),
    (
        "provider_api_key",
        re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}\b"),
    ),
    (
        "authorization_header",
        re.compile(r"(?i)\bAuthorization\s*:\s*(?:Bearer|Basic)\s+[^\s,;]+"),
    ),
    (
        "session_token",
        re.compile(r"(?i)\b(session[_-]?token|sessionid|csrf[_-]?token)\b\s*[:=]\s*['\"]?[^'\"\s,;]+"),
    ),
    (
        "browser_cookie",
        re.compile(r"(?i)\b(cookie|set-cookie)\b\s*:\s*[^\n\r]+"),
    ),
    (
        "password",
        re.compile(r"(?i)\b(password|passwd|pwd)\b\s*[:=]\s*['\"]?[^'\"\s,;]+"),
    ),
    (
        "app_key",
        re.compile(r"(?i)\b(app[_-]?key|odysseus[_-]?app[_-]?key)\b\s*[:=]\s*['\"]?[^'\"\s,;]+"),
    ),
    (
        "generic_secret",
        re.compile(r"(?i)\b(api[_-]?key|secret|token)\b\s*[:=]\s*['\"]?[^'\"\s,;]+"),
    ),
)


def hash_content(content: str | bytes | None) -> str:
    """
    Return a SHA-256 digest for sensitive content without storing the content.

    Args:
        content: Text or bytes that may contain private user data.

    Returns:
        Hex-encoded SHA-256 digest of the input bytes. ``None`` hashes as an
        empty byte string so callers can use the function unconditionally.
    """
    if content is None:
        raw = b""
    elif isinstance(content, bytes):
        raw = content
    else:
        raw = content.encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()


def detect_secret_types(text: str | bytes | None) -> list[str]:
    """
    Identify classes of secret-like values present in text.

    Args:
        text: Potentially sensitive text or bytes.

    Returns:
        Sorted unique secret type names. The names are intentionally generic so
        audit metadata remains useful without revealing the secret value itself.
    """
    if text is None:
        return []
    value = text.decode("utf-8", errors="replace") if isinstance(text, bytes) else str(text)
    return sorted({name for name, pattern in _SECRET_PATTERNS if pattern.search(value)})


def redact_secret_like_values(text: str | bytes | None) -> str:
    """
    Replace known secret-like values with stable redaction markers.

    Args:
        text: Text that may contain provider keys, session tokens, passwords,
            cookies, SSH keys, GPG keys, app keys, or generic secrets.

    Returns:
        Redacted text safe for bounded audit excerpts.
    """
    if text is None:
        return ""

    redacted = text.decode("utf-8", errors="replace") if isinstance(text, bytes) else str(text)
    for name, pattern in _SECRET_PATTERNS:
        redacted = pattern.sub(f"[REDACTED:{name}]", redacted)
    return redacted


def summarize_sensitive_text(
    content: str | bytes | None,
    *,
    content_kind: str = "text",
    max_excerpt_chars: int = 160,
) -> dict[str, object]:
    """
    Build a redacted, bounded summary for sensitive text.

    Args:
        content: Raw sensitive content. This value is never returned directly.
        content_kind: Caller-provided category such as ``prompt``, ``email``,
            ``path_denial``, or ``log``.
        max_excerpt_chars: Maximum characters to include after redaction.

    Returns:
        JSON-serializable summary containing a hash, size metadata, a redacted
        excerpt, detected secret classes, and ``raw_content_logged=False``.
    """
    if content is None:
        raw_text = ""
        raw_bytes = b""
    elif isinstance(content, bytes):
        raw_bytes = content
        raw_text = content.decode("utf-8", errors="replace")
    else:
        raw_text = str(content)
        raw_bytes = raw_text.encode("utf-8", errors="replace")

    redacted = redact_secret_like_values(raw_text)
    excerpt = redacted[: max(0, max_excerpt_chars)]
    if len(redacted) > len(excerpt):
        excerpt += "…"

    return {
        "content_kind": content_kind,
        "content_hash": hash_content(raw_bytes),
        "byte_count": len(raw_bytes),
        "line_count": raw_text.count("\n") + (1 if raw_text else 0),
        "redacted_excerpt": excerpt,
        "secret_type_detected": detect_secret_types(raw_text),
        "raw_content_logged": False,
    }


def _redact_metadata(value: Any, *, parent_key: object | None = None) -> Any:
    """
    Recursively redact metadata values before they are persisted.

    Audit metadata is structured data, so both key names and value patterns
    matter. Short secrets like test passwords may not match token regexes, but a
    value under a key named ``password`` is still sensitive and must not be
    written verbatim to SQLite.
    """
    if _is_sensitive_metadata_key(parent_key):
        return "[REDACTED]"

    if isinstance(value, Mapping):
        return {
            str(key): _redact_metadata(item, parent_key=key)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple, set)):
        return [_redact_metadata(item, parent_key=parent_key) for item in value]

    if isinstance(value, bytes):
        return redact_secret_like_values(value)
    if isinstance(value, str):
        return redact_secret_like_values(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact_secret_like_values(str(value))


def build_redacted_summary(
    content: str | bytes | None = None,
    *,
    content_kind: str = "text",
    metadata: Mapping[str, Any] | None = None,
    max_excerpt_chars: int = 160,
) -> dict[str, object]:
    """
    Combine sensitive text summary and redacted structured metadata.

    Args:
        content: Optional raw content to summarize without storing.
        content_kind: Category stored with the summary for reviewer context.
        metadata: Optional structured fields such as path counts, tool names, or
            denial categories. String metadata is redacted before persistence.
        max_excerpt_chars: Maximum redacted excerpt length.

    Returns:
        JSON-serializable audit summary suitable for storage in
        ``ToolAuditStore``.
    """
    summary = summarize_sensitive_text(
        content,
        content_kind=content_kind,
        max_excerpt_chars=max_excerpt_chars,
    )
    if metadata:
        summary["metadata"] = _redact_metadata(metadata)
    return summary


def summary_to_json(summary: Mapping[str, Any] | None) -> str:
    """
    Serialize a redacted summary with deterministic key ordering.

    Args:
        summary: Summary produced by ``build_redacted_summary`` or compatible
            JSON-serializable metadata.

    Returns:
        UTF-8 JSON text for SQLite storage.
    """
    return json.dumps(summary or {}, sort_keys=True, separators=(",", ":"))
