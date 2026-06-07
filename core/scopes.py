"""
Central API-scope registry for Odysseus API tokens.

All API-token creation and route authorization should import scopes from this
module so routes cannot require scopes that users are unable to grant.
"""

from __future__ import annotations

from enum import Enum
from typing import Iterable


class ApiScope(str, Enum):
    """
    Canonical API-token scopes supported by Odysseus.

    The registry intentionally includes existing read/write/draft scopes plus
    cookbook scopes so this hardening change fixes scope drift without removing
    previously grantable capabilities.
    """

    CHAT = "chat"
    TODOS_READ = "todos:read"
    TODOS_WRITE = "todos:write"
    DOCUMENTS_READ = "documents:read"
    DOCUMENTS_WRITE = "documents:write"
    EMAIL_READ = "email:read"
    EMAIL_DRAFT = "email:draft"
    EMAIL_SEND = "email:send"
    CALENDAR_READ = "calendar:read"
    CALENDAR_WRITE = "calendar:write"
    MEMORY_READ = "memory:read"
    MEMORY_WRITE = "memory:write"
    COOKBOOK_READ = "cookbook:read"
    COOKBOOK_LAUNCH = "cookbook:launch"


# Set of raw string values used by request validation and tests.
ALL_API_SCOPES: set[str] = {scope.value for scope in ApiScope}


def normalize_api_scopes(scopes: str | Iterable[str] | None) -> list[str]:
    """
    Normalize and validate API-token scopes.

    Args:
        scopes: Comma-delimited string or iterable of raw scope strings.

    Returns:
        Sorted unique scope strings.

    Raises:
        ValueError: If any requested scope is not in ``ApiScope``.
    """
    if scopes is None:
        return []

    if isinstance(scopes, str):
        raw_scopes = scopes.split(",")
    else:
        raw_scopes = list(scopes)

    normalized = sorted({str(scope).strip() for scope in raw_scopes if str(scope).strip()})
    unknown = sorted(set(normalized) - ALL_API_SCOPES)
    if unknown:
        raise ValueError("Unknown API token scope(s): " + ", ".join(unknown))

    return normalized
