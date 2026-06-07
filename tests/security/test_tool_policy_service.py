"""
Security tests for the tool-policy decision service.

The decision service must be testable without invoking real tools. These tests
verify fail-closed authorization behavior for allow, deny, stage, and review
outcomes.
"""

from types import MappingProxyType

from core.scopes import ApiScope
from core.tool_policy import ToolPolicy
from services.tool_policy_service import ToolPolicyRequest, ToolPolicyService


def _service_for(*policies: ToolPolicy) -> ToolPolicyService:
    """
    Build a service with an immutable test registry.

    Args:
        policies: Static test policies owned by the test, not request data.

    Returns:
        ToolPolicyService using only the supplied policies.
    """
    return ToolPolicyService(MappingProxyType({policy.name: policy for policy in policies}))


def _request(**overrides) -> ToolPolicyRequest:
    """
    Build a default authenticated request for concise decision tests.

    Args:
        overrides: Field overrides for the request.

    Returns:
        ToolPolicyRequest with safe defaults.
    """
    values = {
        "requesting_user": "alice",
        "session_id": "session-1",
        "tool_name": "safe.status",
        "api_scopes": frozenset(),
        "admin_status": False,
        "deployment_mode": "local",
        "offline_mode": False,
        "confirmation_id": None,
        "sandbox_available": False,
        "requested_paths": tuple(),
        "network_requested": False,
    }
    values.update(overrides)
    return ToolPolicyRequest(**values)


def test_unknown_tool_denies():
    # Unknown tools must fail closed because no static application policy exists.
    decision = ToolPolicyService(registry=MappingProxyType({})).decide(
        _request(tool_name="unknown.tool")
    )

    assert decision.decision == "deny"
    assert decision.reason == "tool is not registered"
    assert decision.audit_required is True


def test_disabled_tool_denies():
    # Disabled tools are explicit denials, not unknown tools.
    service = _service_for(
        ToolPolicy(
            name="safe.status",
            description="Disabled status policy.",
            risk="low",
            enabled=False,
        )
    )

    decision = service.decide(_request())

    assert decision.decision == "deny"
    assert decision.reason == "tool is disabled"


def test_unauthenticated_user_denies():
    # Tool requests require an authenticated user before any other privilege is
    # considered.
    service = _service_for(
        ToolPolicy(name="safe.status", description="Read status.", risk="low")
    )

    decision = service.decide(_request(requesting_user=None))

    assert decision.decision == "deny"
    assert decision.reason == "authentication is required"


def test_non_admin_cannot_use_admin_required_tool():
    # Admin-only tools must not be usable by ordinary authenticated users.
    service = _service_for(
        ToolPolicy(
            name="file.write",
            description="Write files.",
            risk="high",
            admin_required=True,
            confirmation_required=True,
            audit_required=True,
        )
    )

    decision = service.decide(_request(tool_name="file.write", admin_status=False))

    assert decision.decision == "deny"
    assert decision.reason == "admin privileges are required"


def test_missing_api_scope_denies_scoped_tool():
    # Scoped tools must require a grantable API scope before proceeding.
    service = _service_for(
        ToolPolicy(
            name="safe.scoped",
            description="Scoped status policy.",
            risk="low",
            required_scope=ApiScope.CHAT.value,
        )
    )

    decision = service.decide(_request(tool_name="safe.scoped", api_scopes=frozenset()))

    assert decision.decision == "deny"
    assert decision.reason == "required API scope is missing"


def test_offline_mode_denies_network_requesting_tool():
    # Offline mode blocks network use even when the policy normally allows it.
    service = _service_for(
        ToolPolicy(
            name="web_research.run",
            description="Research web content.",
            risk="medium",
            network_allowed=True,
            audit_required=True,
        )
    )

    decision = service.decide(
        _request(
            tool_name="web_research.run",
            offline_mode=True,
            network_requested=True,
        )
    )

    assert decision.decision == "deny"
    assert decision.reason == "offline mode blocks network access"


def test_network_request_denies_when_policy_disallows_network():
    # A request cannot gain network access unless the static policy grants it.
    service = _service_for(
        ToolPolicy(name="safe.status", description="Read status.", risk="low")
    )

    decision = service.decide(_request(network_requested=True))

    assert decision.decision == "deny"
    assert decision.reason == "tool policy does not allow network access"


def test_confirmation_required_tool_returns_review_required_without_confirmation():
    # Missing confirmation should route the user to a review/approval flow rather
    # than allowing a high-risk action to run.
    service = _service_for(
        ToolPolicy(
            name="email.send",
            description="Send email.",
            risk="high",
            admin_required=True,
            confirmation_required=True,
            audit_required=True,
        )
    )

    decision = service.decide(
        _request(tool_name="email.send", admin_status=True, confirmation_id=None)
    )

    assert decision.decision == "review_required"
    assert decision.requires_confirmation is True


def test_staging_required_tool_returns_stage_when_not_confirmed():
    # This test uses a staging-only policy so the staging branch is independently
    # covered apart from confirmation-required tools.
    service = _service_for(
        ToolPolicy(
            name="draft.patch",
            description="Stage a generated patch.",
            risk="medium",
            staging_required=True,
            audit_required=True,
        )
    )

    decision = service.decide(_request(tool_name="draft.patch", confirmation_id=None))

    assert decision.decision == "stage"
    assert decision.requires_staging is True


def test_sandbox_required_tool_denies_when_sandbox_unavailable():
    # Critical execution tools must not run if the configured sandbox backend is
    # unavailable.
    service = _service_for(
        ToolPolicy(
            name="python.run",
            description="Run Python code.",
            risk="critical",
            admin_required=True,
            confirmation_required=True,
            sandbox_required=True,
            audit_required=True,
        )
    )

    decision = service.decide(
        _request(
            tool_name="python.run",
            admin_status=True,
            sandbox_available=False,
            confirmation_id="confirm-1",
        )
    )

    assert decision.decision == "deny"
    assert decision.reason == "required sandbox is unavailable"


def test_valid_low_risk_tool_can_allow():
    # A low-risk authenticated request with all requirements satisfied should be
    # allowed, proving the service is not deny-only.
    service = _service_for(
        ToolPolicy(name="safe.status", description="Read status.", risk="low")
    )

    decision = service.decide(_request())

    assert decision.decision == "allow"
    assert decision.reason == "tool policy requirements satisfied"
    assert decision.risk == "low"
