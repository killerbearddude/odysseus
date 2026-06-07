"""
Database support-boundary helpers for Odysseus alpha deployments.

SQLite is the supported database for the alpha hardening baseline. Other
backends must be explicitly opted into with ``ODYSSEUS_EXPERIMENTAL_DATABASES``
so operators do not accidentally run untested migration paths.
"""

from __future__ import annotations

import os
from urllib.parse import urlparse


SQLITE_SCHEMES = {"", "file", "sqlite", "sqlite+pysqlite"}
EXPERIMENTAL_ENV = "ODYSSEUS_EXPERIMENTAL_DATABASES"


class DatabaseSupportError(ValueError):
    """Raised when a configured database backend is unsupported or invalid."""


def experimental_databases_enabled() -> bool:
    """Return whether non-SQLite databases are explicitly enabled."""
    return os.getenv(EXPERIMENTAL_ENV, "false").lower() in {"1", "true", "yes", "on"}


def validate_database_url(database_url: str | None) -> str:
    """
    Validate the alpha database support boundary.

    Args:
        database_url: Optional ``DATABASE_URL`` value.

    Returns:
        ``sqlite`` for supported SQLite/default URLs or the experimental scheme
        when the operator has opted into unsupported databases.

    Raises:
        DatabaseSupportError: If the URL is malformed or unsupported.
    """
    if not database_url:
        return "sqlite"

    value = database_url.strip()
    if not value:
        return "sqlite"
    if value.startswith("://"):
        raise DatabaseSupportError("DATABASE_URL is invalid; expected sqlite:///path or a filesystem path")

    parsed = urlparse(value)
    scheme = parsed.scheme.lower()

    if scheme in SQLITE_SCHEMES:
        return "sqlite"
    if scheme == "sqlite3":
        raise DatabaseSupportError("DATABASE_URL should use sqlite:///path, not sqlite3://")
    if not scheme and ":" not in value:
        return "sqlite"
    if not scheme:
        raise DatabaseSupportError("DATABASE_URL is invalid; expected sqlite:///path or a filesystem path")

    if experimental_databases_enabled():
        return scheme

    raise DatabaseSupportError(
        f"DATABASE_URL backend '{scheme}' is unsupported in Odysseus alpha; "
        f"use SQLite or set {EXPERIMENTAL_ENV}=1 for experimental testing"
    )
