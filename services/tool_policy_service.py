"""
Decision service for Odysseus tool-policy enforcement.

The service evaluates static registry metadata against request context and
returns a decision object. It deliberately does not execute tools, mutate state,
or accept policy definitions from request-controlled data.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from uuid import uuid4

from core.tool_policy import PolicyDecision, ToolPolicy
from core.tool_registry import TOOL_REGISTRY


@dataclass(frozen=True)
class ToolPolicyRequest:
    """
    Input context for one tool-policy decision.

    The requested tool name and contextual facts may come from a route, but the
    policy metadata is always resolved from the application-owned registry.
    """

    requesting_user: str | None
    session_id: str | None
    tool_name: str
    api_scopes: frozenset[str] = field(default_factory=frozenset)
    admin_status: bool = False
    deployment_mode: str = "local"
    offline_mode: bool = False
    confirmation_id: str | None = None
    sandbox_available: bool = False
    requested_paths: tuple[str, ...] = field(default_factory=tuple)
    network_requested: bool = False

    @classmethod
    def from_iterables(
        cls,
        *,
        requesting_user: str | None,
        session_id: str | None,
        tool_name: str,
        api_scopes: Iterable[str] | None = None,
        admin_status: bool = False,
        deployment_mode: str = "local",
        offline_mode: bool = False,
        confirmation_id: str | None = None,
        sandbox_available: bool = False,
        requested_paths: Iterable[str] | None = None,
        network_requested: bool = False,
    ) -> "ToolPolicyRequest":
        """
        Create a request while normalizing iterable fields.

        Args:
            requesting_user: Authenticated user identifier, or None.
            session_id: Current session identifier, if available.
            tool_name: Requested tool identifier.
            api_scopes: API scopes held by the caller.
            admin_status: Whether the caller has admin privileges.
            deployment_mode: Active deployment mode string.
            offline_mode: Whether offline/local-only mode is active.
            confirmation_id: Human confirmation token or identifier, if present.
            sandbox_available: Whether a required sandbox backend is available.
            requested_paths: Paths requested by the tool call. Path validation is
                intentionally deferred to the path-safety PR.
            network_requested: Whether this invocation wants network access.

        Returns:
            Normalized immutable request object.
        """
        return cls(
            requesting_user=requesting_user,
            session_id=session_id,
            tool_name=tool_name,
            api_scopes=frozenset(api_scopes or ()),
            admin_status=admin_status,
            deployment_mode=deployment_mode,
            offline_mode=offline_mode,
            confirmation_id=confirmation_id,
            sandbox_available=sandbox_available,
            requested_paths=tuple(requested_paths or ()),
            network_requested=network_requested,
        )


@dataclass(frozen=True)
class ToolPolicyDecision:
    """
    Result of evaluating one tool request against static policy.

    The reason is designed to be user-visible and operationally useful while
    avoiding secret-bearing details such as raw arguments, paths, or tokens.
    """

    decision_id: str
    tool_name: str
    decision: PolicyDecision
    reason: str
    risk: str | None
    requires_confirmation: bool
    requires_sandbox: bool
    requires_staging: bool
    audit_required: bool


class ToolPolicyService:
    """
    Evaluates tool requests against a static policy registry.

    A registry may be injected by tests or application bootstrap code, but it is
    intentionally fixed for the lifetime of the service instance. Request data
    cannot add, remove, or weaken policies.
    """

    def __init__(self, registry: Mapping[str, ToolPolicy] | None = None) -> None:
        """
        Initialize the service.

        Args:
            registry: Optional application-owned registry. Defaults to the
                central registry in ``core.tool_registry``.
        """
        self._registry = registry if registry is not None else TOOL_REGISTRY

    def decide(self, request: ToolPolicyRequest) -> ToolPolicyDecision:
        """
        Decide whether a tool invocation can proceed.

        Args:
            request: Normalized request context.

        Returns:
            A fail-closed policy decision. The method does not execute tools.
        """
        policy = self._registry.get(request.tool_name)
        if policy is None:
            return self._decision(
                request.tool_name,
                "deny",
                "tool is not registered",
                None,
                requires_confirmation=False,
                requires_sandbox=False,
                requires_staging=False,
                audit_required=True,
            )

        if not policy.enabled:
            return self._from_policy(policy, "deny", "tool is disabled")

        if not request.requesting_user:
            return self._from_policy(policy, "deny", "authentication is required")

        if policy.admin_required and not request.admin_status:
            return self._from_policy(policy, "deny", "admin privileges are required")

        if policy.required_scope and policy.required_scope not in request.api_scopes:
            return self._from_policy(policy, "deny", "required API scope is missing")

        if policy.sandbox_required and not request.sandbox_available:
            return self._from_policy(policy, "deny", "required sandbox is unavailable")

        if request.offline_mode and request.network_requested:
            return self._from_policy(policy, "deny", "offline mode blocks network access")

        # A tool that does not declare network access must not receive network
        # capability just because a request asked for it.
        if request.network_requested and not policy.network_allowed:
            return self._from_policy(policy, "deny", "tool policy does not allow network access")

        if policy.confirmation_required and not request.confirmation_id:
            return self._from_policy(
                policy,
                "review_required",
                "human confirmation is required before this tool can run",
            )

        if policy.staging_required and not request.confirmation_id:
            return self._from_policy(
                policy,
                "stage",
                "tool output must be staged for review before execution",
            )

        return self._from_policy(policy, "allow", "tool policy requirements satisfied")

    def _from_policy(
        self,
        policy: ToolPolicy,
        decision: PolicyDecision,
        reason: str,
    ) -> ToolPolicyDecision:
        """
        Build a decision result from known policy metadata.

        Args:
            policy: Registered tool policy.
            decision: Policy outcome.
            reason: User-visible reason with no raw secret-bearing request data.

        Returns:
            Tool policy decision object.
        """
        return self._decision(
            policy.name,
            decision,
            reason,
            policy.risk,
            requires_confirmation=policy.confirmation_required,
            requires_sandbox=policy.sandbox_required,
            requires_staging=policy.staging_required,
            audit_required=policy.audit_required,
        )

    @staticmethod
    def _decision(
        tool_name: str,
        decision: PolicyDecision,
        reason: str,
        risk: str | None,
        *,
        requires_confirmation: bool,
        requires_sandbox: bool,
        requires_staging: bool,
        audit_required: bool,
    ) -> ToolPolicyDecision:
        """
        Construct a decision with a unique identifier.

        Args:
            tool_name: Requested tool name.
            decision: Policy outcome.
            reason: User-visible reason.
            risk: Registered risk, or None for unknown tools.
            requires_confirmation: Whether the policy requires confirmation.
            requires_sandbox: Whether the policy requires a sandbox.
            requires_staging: Whether the policy requires staging.
            audit_required: Whether the decision should be audited.

        Returns:
            Immutable decision object.
        """
        return ToolPolicyDecision(
            decision_id=str(uuid4()),
            tool_name=tool_name,
            decision=decision,
            reason=reason,
            risk=risk,
            requires_confirmation=requires_confirmation,
            requires_sandbox=requires_sandbox,
            requires_staging=requires_staging,
            audit_required=audit_required,
        )


__all__ = [
    "ToolPolicyDecision",
    "ToolPolicyRequest",
    "ToolPolicyService",
]
