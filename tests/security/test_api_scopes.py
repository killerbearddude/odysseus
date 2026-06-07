"""
Security tests for the canonical API-token scope registry.

These tests prevent drift where token creation exposes one set of scopes while
routes require another set that users cannot grant.
"""

from pathlib import Path
import ast

import pytest

from core.scopes import ALL_API_SCOPES, ApiScope, normalize_api_scopes
from routes import api_token_routes


_SCOPE_PREFIXES = ("todos:", "documents:", "email:", "calendar:", "memory:", "cookbook:")


def _scope_literals_in_file(path: Path) -> set[str]:
    """
    Return scope-looking string literals from a Python source file.

    AST parsing avoids fragile regex quoting and catches direct hardcoded route
    scope strings without matching comments or prose.
    """
    tree = ast.parse(path.read_text(), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            value = node.value
            if value == "chat" or value.startswith(_SCOPE_PREFIXES):
                found.add(value)
    return found


def test_registry_contains_expected_cookbook_scopes():
    # Prevents the regression where Codex/Cookbook routes required scopes that
    # could not be granted during API-token creation.
    assert ApiScope.COOKBOOK_READ.value in ALL_API_SCOPES
    assert ApiScope.COOKBOOK_LAUNCH.value in ALL_API_SCOPES


def test_token_creation_uses_canonical_scope_registry():
    # Ensures the API-token route delegates its allowed-scope list to the central
    # registry instead of maintaining a separate hardcoded set.
    assert api_token_routes.ALLOWED_SCOPES == ALL_API_SCOPES


def test_token_profiles_reference_only_registered_scopes():
    # Token profiles are shortcuts for creating scoped tokens, so every profile
    # value must be grantable through the central registry.
    profile_scopes = {
        scope
        for scopes in api_token_routes.TOKEN_PROFILES.values()
        for scope in scopes
    }

    assert profile_scopes <= ALL_API_SCOPES


def test_unknown_scopes_are_rejected():
    # Unknown scopes must fail validation instead of being silently accepted into
    # token records where no route policy understands them.
    with pytest.raises(ValueError):
        normalize_api_scopes(["chat", "not-a-real-scope"])


def test_cookbook_scopes_can_be_granted():
    # Confirms both required cookbook scopes normalize successfully and therefore
    # can be used by API-token creation flows.
    assert normalize_api_scopes(["cookbook:read", "cookbook:launch"]) == [
        "cookbook:launch",
        "cookbook:read",
    ]


def test_scoped_routes_do_not_reference_undefined_scopes():
    # Scans the route files touched by this PR so new route-level scope strings
    # cannot drift outside the central registry.
    route_files = [
        Path("routes/api_token_routes.py"),
        Path("routes/codex_routes.py"),
    ]

    referenced_scopes: set[str] = set()
    for route_file in route_files:
        referenced_scopes.update(_scope_literals_in_file(route_file))

    assert referenced_scopes <= ALL_API_SCOPES
