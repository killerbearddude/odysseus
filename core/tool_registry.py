"""
Static registry for Odysseus tool policies.

The registry is the application-owned source of truth for declared tool risk and
required controls. Model output, browser requests, and tool arguments may request
a tool by name, but they must not define or override policy metadata.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from core.scopes import ALL_API_SCOPES
from core.tool_policy import ToolPolicy, VALID_TOOL_RISKS


# These names are the first dangerous tool surface area captured by policy.
# Enforcement will be wired into individual routes/tools in later PRs; declaring
# them here makes the future authorization boundary explicit and testable now.
_REGISTERED_TOOL_POLICIES: tuple[ToolPolicy, ...] = (
    ToolPolicy(
        name="shell.run",
        description="Run a shell command on behalf of the user.",
        risk="critical",
        admin_required=True,
        confirmation_required=True,
        sandbox_required=True,
        staging_required=True,
        audit_required=True,
    ),
    ToolPolicy(
        name="python.run",
        description="Run Python code generated or requested through Odysseus.",
        risk="critical",
        admin_required=True,
        confirmation_required=True,
        sandbox_required=True,
        staging_required=True,
        audit_required=True,
    ),
    ToolPolicy(
        name="file.write",
        description="Write or modify files in an Odysseus-controlled workspace.",
        risk="high",
        admin_required=True,
        confirmation_required=True,
        staging_required=True,
        audit_required=True,
    ),
    ToolPolicy(
        name="background_job.create",
        description="Create a background job or scheduler task.",
        risk="high",
        admin_required=True,
        confirmation_required=True,
        staging_required=True,
        audit_required=True,
    ),
    ToolPolicy(
        name="model.download",
        description="Download model weights or model-serving artifacts.",
        risk="critical",
        admin_required=True,
        confirmation_required=True,
        sandbox_required=True,
        network_allowed=True,
        staging_required=True,
        audit_required=True,
    ),
    ToolPolicy(
        name="model.serve",
        description="Launch or modify model-serving processes.",
        risk="critical",
        admin_required=True,
        confirmation_required=True,
        sandbox_required=True,
        staging_required=True,
        audit_required=True,
    ),
    ToolPolicy(
        name="email.send",
        description="Send email through a configured account or integration.",
        risk="high",
        admin_required=True,
        confirmation_required=True,
        network_allowed=True,
        staging_required=True,
        audit_required=True,
    ),
    ToolPolicy(
        name="backup.restore",
        description="Restore application data from a backup artifact.",
        risk="critical",
        admin_required=True,
        confirmation_required=True,
        sandbox_required=True,
        staging_required=True,
        audit_required=True,
    ),
    ToolPolicy(
        name="import.run",
        description="Import external user-provided data into Odysseus storage.",
        risk="high",
        admin_required=True,
        confirmation_required=True,
        staging_required=True,
        audit_required=True,
    ),
    ToolPolicy(
        name="export.run",
        description="Export user data or generated artifacts from Odysseus.",
        risk="high",
        admin_required=True,
        confirmation_required=True,
        staging_required=True,
        audit_required=True,
    ),
    ToolPolicy(
        name="web_research.run",
        description="Fetch or research external web content.",
        risk="medium",
        network_allowed=True,
        audit_required=True,
    ),
    ToolPolicy(
        name="document.ingest",
        description="Ingest documents into local processing or indexing pipelines.",
        risk="high",
        admin_required=True,
        confirmation_required=True,
        staging_required=True,
        audit_required=True,
    ),
)


def _validate_policy(policy: ToolPolicy) -> None:
    """
    Validate one policy before it is exposed through the registry.

    Args:
        policy: Static application-owned policy metadata.

    Raises:
        ValueError: If the policy violates a fail-closed security invariant.
    """
    if not policy.name.strip():
        raise ValueError("tool policy name must not be empty")
    if not policy.description.strip():
        raise ValueError(f"tool policy {policy.name!r} must have a description")
    if policy.risk not in VALID_TOOL_RISKS:
        raise ValueError(f"tool policy {policy.name!r} has invalid risk {policy.risk!r}")
    if policy.required_scope is not None and policy.required_scope not in ALL_API_SCOPES:
        raise ValueError(
            f"tool policy {policy.name!r} requires unknown API scope "
            f"{policy.required_scope!r}"
        )

    # Critical tools represent direct execution, model-serving, or destructive
    # restore operations. Keep the required controls coupled so later route
    # wiring cannot accidentally register a weaker critical tool.
    if policy.risk == "critical":
        if not policy.admin_required:
            raise ValueError(f"critical tool {policy.name!r} must require admin")
        if not policy.confirmation_required:
            raise ValueError(f"critical tool {policy.name!r} must require confirmation")
        if not policy.sandbox_required:
            raise ValueError(f"critical tool {policy.name!r} must require sandbox")
        if not policy.audit_required:
            raise ValueError(f"critical tool {policy.name!r} must require audit")

    # High-risk tools may write files, send data, or mutate persistent state.
    # They do not all require sandboxing yet, but they must require human review
    # and auditability before execution routes are wired in.
    if policy.risk == "high":
        if not policy.admin_required:
            raise ValueError(f"high-risk tool {policy.name!r} must require admin")
        if not policy.confirmation_required:
            raise ValueError(f"high-risk tool {policy.name!r} must require confirmation")
        if not policy.audit_required:
            raise ValueError(f"high-risk tool {policy.name!r} must require audit")


def validate_tool_registry(policies: tuple[ToolPolicy, ...] = _REGISTERED_TOOL_POLICIES) -> None:
    """
    Validate a collection of tool policies.

    Args:
        policies: Static policies to validate. Tests may pass custom policies to
            prove invariants fail closed without mutating the application registry.

    Raises:
        ValueError: If names are duplicated or any policy violates invariants.
    """
    seen: set[str] = set()
    for policy in policies:
        if policy.name in seen:
            raise ValueError(f"duplicate tool policy name: {policy.name!r}")
        seen.add(policy.name)
        _validate_policy(policy)


def build_tool_registry(
    policies: tuple[ToolPolicy, ...] = _REGISTERED_TOOL_POLICIES,
) -> Mapping[str, ToolPolicy]:
    """
    Build an immutable name-to-policy mapping.

    Args:
        policies: Static policies to expose.

    Returns:
        Read-only mapping keyed by tool name.
    """
    validate_tool_registry(policies)
    return MappingProxyType({policy.name: policy for policy in policies})


# Validate at import time so a bad policy fails before request handling. The
# MappingProxyType prevents accidental mutation by application code after import.
TOOL_REGISTRY: Mapping[str, ToolPolicy] = build_tool_registry()


def get_tool_policy(tool_name: str) -> ToolPolicy | None:
    """
    Look up a registered tool policy by name.

    Args:
        tool_name: Tool identifier requested by a route or service.

    Returns:
        The registered policy, or None when the tool is unknown.
    """
    return TOOL_REGISTRY.get(tool_name)


__all__ = [
    "TOOL_REGISTRY",
    "build_tool_registry",
    "get_tool_policy",
    "validate_tool_registry",
]
