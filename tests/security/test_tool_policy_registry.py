"""
Security tests for the central tool-policy registry.

These tests lock in the static registry as the first application-owned authority
surface for dangerous tool declarations.
"""

import pytest

from core.scopes import ALL_API_SCOPES
from core.tool_policy import ToolPolicy, VALID_TOOL_RISKS
from core.tool_registry import TOOL_REGISTRY, build_tool_registry, validate_tool_registry


EXPECTED_TOOL_NAMES = {
    "shell.run",
    "python.run",
    "file.write",
    "background_job.create",
    "model.download",
    "model.serve",
    "email.send",
    "backup.restore",
    "import.run",
    "export.run",
    "web_research.run",
    "document.ingest",
}


def test_registry_contains_initial_dangerous_tools():
    # Ensures the first policy surface covers the dangerous tools called out by
    # the roadmap before route-level enforcement is wired in.
    assert set(TOOL_REGISTRY) == EXPECTED_TOOL_NAMES


def test_every_registered_tool_has_unique_name():
    # The immutable registry is keyed by name, so duplicates must fail before a
    # later policy silently overwrites an earlier one.
    names = [policy.name for policy in TOOL_REGISTRY.values()]
    assert len(names) == len(set(names))


def test_every_registered_risk_level_is_valid():
    # Prevents future tools from inventing risk levels that the decision service
    # and UI cannot reason about consistently.
    assert {policy.risk for policy in TOOL_REGISTRY.values()} <= VALID_TOOL_RISKS


def test_registered_tool_required_scopes_exist_in_api_scope_registry():
    # Keeps tool policy scopes aligned with the central API-token scope registry.
    required_scopes = {
        policy.required_scope
        for policy in TOOL_REGISTRY.values()
        if policy.required_scope is not None
    }
    assert required_scopes <= ALL_API_SCOPES


def test_build_registry_rejects_duplicate_tool_names():
    # Duplicate names are a policy-shadowing risk and must fail closed.
    duplicate = (
        ToolPolicy(name="safe.status", description="Read status.", risk="low"),
        ToolPolicy(name="safe.status", description="Read status again.", risk="low"),
    )

    with pytest.raises(ValueError, match="duplicate tool policy name"):
        build_tool_registry(duplicate)


def test_disabled_policy_is_still_registered_for_explicit_denial():
    # Disabled tools remain visible to the decision service so users get a clear
    # deny reason instead of an ambiguous unknown-tool response.
    policy = ToolPolicy(
        name="safe.disabled",
        description="Disabled test policy.",
        risk="low",
        enabled=False,
    )
    registry = build_tool_registry((policy,))

    assert registry["safe.disabled"] == policy
