"""
Invariant tests for tool-policy risk controls.

The registry must fail closed when future dangerous tools are declared without
required authorization, confirmation, sandbox, or audit controls.
"""

import pytest

from core.tool_policy import ToolPolicy
from core.tool_registry import TOOL_REGISTRY, validate_tool_registry


def test_critical_registered_tools_require_admin_confirmation_sandbox_and_audit():
    # Critical tools can execute code, download models, serve processes, or
    # restore data, so they must always carry the strongest near-term controls.
    critical = [policy for policy in TOOL_REGISTRY.values() if policy.risk == "critical"]
    assert critical
    for policy in critical:
        assert policy.admin_required is True
        assert policy.confirmation_required is True
        assert policy.sandbox_required is True
        assert policy.audit_required is True


def test_high_risk_registered_tools_require_admin_confirmation_and_audit():
    # High-risk tools can mutate data or send information. They may not all have
    # sandboxing yet, but they must require admin, confirmation, and auditing.
    high_risk = [policy for policy in TOOL_REGISTRY.values() if policy.risk == "high"]
    assert high_risk
    for policy in high_risk:
        assert policy.admin_required is True
        assert policy.confirmation_required is True
        assert policy.audit_required is True


@pytest.mark.parametrize(
    "policy, expected_message",
    [
        (
            ToolPolicy(
                name="bad.critical.no_admin",
                description="Invalid critical policy.",
                risk="critical",
                confirmation_required=True,
                sandbox_required=True,
                audit_required=True,
            ),
            "must require admin",
        ),
        (
            ToolPolicy(
                name="bad.critical.no_confirmation",
                description="Invalid critical policy.",
                risk="critical",
                admin_required=True,
                sandbox_required=True,
                audit_required=True,
            ),
            "must require confirmation",
        ),
        (
            ToolPolicy(
                name="bad.critical.no_sandbox",
                description="Invalid critical policy.",
                risk="critical",
                admin_required=True,
                confirmation_required=True,
                audit_required=True,
            ),
            "must require sandbox",
        ),
        (
            ToolPolicy(
                name="bad.critical.no_audit",
                description="Invalid critical policy.",
                risk="critical",
                admin_required=True,
                confirmation_required=True,
                sandbox_required=True,
            ),
            "must require audit",
        ),
    ],
)
def test_invalid_critical_tool_invariants_are_rejected(policy, expected_message):
    # Custom policies prove validation behavior without weakening the central
    # application registry.
    with pytest.raises(ValueError, match=expected_message):
        validate_tool_registry((policy,))


@pytest.mark.parametrize(
    "policy, expected_message",
    [
        (
            ToolPolicy(
                name="bad.high.no_admin",
                description="Invalid high-risk policy.",
                risk="high",
                confirmation_required=True,
                audit_required=True,
            ),
            "must require admin",
        ),
        (
            ToolPolicy(
                name="bad.high.no_confirmation",
                description="Invalid high-risk policy.",
                risk="high",
                admin_required=True,
                audit_required=True,
            ),
            "must require confirmation",
        ),
        (
            ToolPolicy(
                name="bad.high.no_audit",
                description="Invalid high-risk policy.",
                risk="high",
                admin_required=True,
                confirmation_required=True,
            ),
            "must require audit",
        ),
    ],
)
def test_invalid_high_risk_tool_invariants_are_rejected(policy, expected_message):
    # High-risk registration must fail before request-time decisions can depend
    # on an under-specified policy.
    with pytest.raises(ValueError, match=expected_message):
        validate_tool_registry((policy,))


def test_unknown_risk_level_is_rejected():
    # Runtime code should never need to guess what an undeclared risk means.
    bad_policy = ToolPolicy(
        name="bad.risk",
        description="Invalid risk policy.",
        risk="extreme",  # type: ignore[arg-type]
    )

    with pytest.raises(ValueError, match="invalid risk"):
        validate_tool_registry((bad_policy,))


def test_unknown_required_scope_is_rejected():
    # Required scopes must be grantable through the API-token registry.
    bad_policy = ToolPolicy(
        name="bad.scope",
        description="Invalid scope policy.",
        risk="low",
        required_scope="not:a-real-scope",
    )

    with pytest.raises(ValueError, match="unknown API scope"):
        validate_tool_registry((bad_policy,))
