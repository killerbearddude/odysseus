"""
Security tests for audit redaction helpers.

These tests prevent regressions where persistent audit summaries accidentally
store provider keys, app keys, session tokens, private-key material, full email
bodies, or full prompts.
"""

from __future__ import annotations

import json

from core.audit_redaction import (
    build_redacted_summary,
    detect_secret_types,
    hash_content,
    redact_secret_like_values,
    summarize_sensitive_text,
)


def _summary_json(summary: dict[str, object]) -> str:
    """Serialize summaries so tests can search all persisted fields."""
    return json.dumps(summary, sort_keys=True)


def test_api_keys_are_redacted():
    # Prevents provider API keys from being persisted in audit excerpts.
    raw = "OPENAI_API_KEY=sk-testsecretvalue1234567890"
    redacted = redact_secret_like_values(raw)

    assert "sk-testsecretvalue" not in redacted
    assert "REDACTED" in redacted
    assert "provider_api_key" in detect_secret_types(raw) or "generic_secret" in detect_secret_types(raw)


def test_session_tokens_are_redacted():
    # Prevents bearer/session credentials from leaking through metadata logs.
    raw = "session_token=abc123supersecret Authorization: Bearer token-value"
    redacted = redact_secret_like_values(raw)

    assert "abc123supersecret" not in redacted
    assert "token-value" not in redacted
    assert "session_token" in detect_secret_types(raw)


def test_password_looking_values_are_redacted():
    # Prevents common password assignment forms from entering persistent audit rows.
    raw = "password=hunter2"
    redacted = redact_secret_like_values(raw)

    assert "hunter2" not in redacted
    assert "password" in detect_secret_types(raw)


def test_ssh_private_key_material_is_redacted():
    # Prevents catastrophic leakage if a tool request accidentally includes a key.
    raw = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc123\n-----END OPENSSH PRIVATE KEY-----"
    redacted = redact_secret_like_values(raw)

    assert "abc123" not in redacted
    assert "ssh_private_key" in detect_secret_types(raw)


def test_email_body_is_summarized_not_stored_raw():
    # Email content may be private; audit should keep only hash/count/excerpt metadata.
    email = "Subject: Private\n\n" + "This is a confidential email body. " * 40
    summary = summarize_sensitive_text(email, content_kind="email", max_excerpt_chars=80)
    encoded = _summary_json(summary)

    assert summary["raw_content_logged"] is False
    assert summary["content_kind"] == "email"
    assert summary["byte_count"] == len(email.encode("utf-8"))
    assert len(str(summary["redacted_excerpt"])) < len(email)
    assert email not in encoded


def test_full_prompt_is_not_stored_by_default():
    # Prompts can contain private documents or clipboard data, so only summaries persist.
    prompt = "Please analyze this private document. " * 60
    summary = build_redacted_summary(prompt, content_kind="prompt", max_excerpt_chars=96)
    encoded = _summary_json(summary)

    assert summary["raw_content_logged"] is False
    assert summary["content_kind"] == "prompt"
    assert prompt not in encoded
    assert hash_content(prompt) == summary["content_hash"]


def test_metadata_values_are_redacted_inside_summary():
    # Structured metadata is also persisted and must receive the same secret treatment.
    summary = build_redacted_summary(
        "short request",
        metadata={"api_key": "sk-testsecretvalue1234567890", "nested": {"password": "hunter2"}},
    )
    encoded = _summary_json(summary)

    assert "sk-testsecretvalue" not in encoded
    assert "hunter2" not in encoded
    assert "REDACTED" in encoded
