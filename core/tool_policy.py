"""
Central tool-policy types for Odysseus.

This module defines the policy metadata used to decide whether a tool can be
allowed, denied, staged, or sent for human review. It is intentionally separate
from tool execution so model-generated tool calls cannot define their own
authorization rules at runtime.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


# Keep risk and decision values narrow so registry validation can fail closed
# when future tools attempt to introduce an undeclared security category.
ToolRisk = Literal["low", "medium", "high", "critical"]
PolicyDecision = Literal["allow", "deny", "stage", "review_required"]

VALID_TOOL_RISKS: frozenset[str] = frozenset(
    {"low", "medium", "high", "critical"}
)
VALID_POLICY_DECISIONS: frozenset[str] = frozenset(
    {"allow", "deny", "stage", "review_required"}
)


@dataclass(frozen=True)
class ToolPolicy:
    """
    Declares the security controls required for one tool.

    Tool policies are static application-owned metadata. They must not be
    supplied by the model, browser, request payload, or user-controlled tool
    arguments.
    """

    name: str
    description: str
    risk: ToolRisk
    required_scope: str | None = None
    admin_required: bool = False
    confirmation_required: bool = False
    sandbox_required: bool = False
    network_allowed: bool = False
    read_roots: tuple[str, ...] = field(default_factory=tuple)
    write_roots: tuple[str, ...] = field(default_factory=tuple)
    staging_required: bool = False
    audit_required: bool = False
    enabled: bool = True
