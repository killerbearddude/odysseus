"""
Migration-discipline tests for Odysseus SQLite alpha support.

The tests use sanitized temporary SQLite databases, not real user data, and
assert idempotency, backup creation, rollback behavior, and database support
boundary enforcement.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from core.database_support import DatabaseSupportError, validate_database_url
from core.migrations import MigrationError, detect_schema_version, migrate_sqlite_database


def _old_db(path: Path) -> Path:
    """Create a sanitized old SQLite fixture in a temporary directory."""
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL)")
        conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT NOT NULL)")
        conn.execute("INSERT INTO users (username) VALUES ('alice')")
        conn.execute("INSERT INTO messages (body) VALUES ('hello')")
        conn.commit()
    return path


def _count(path: Path, table: str) -> int:
    """Return a table row count from a fixture database."""
    with sqlite3.connect(path) as conn:
        return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


def test_sqlite_database_urls_are_supported_by_default(monkeypatch):
    # Regression guard: alpha database support must default to SQLite.
    monkeypatch.delenv("ODYSSEUS_EXPERIMENTAL_DATABASES", raising=False)

    assert validate_database_url(None) == "sqlite"
    assert validate_database_url("sqlite:///data/app.db") == "sqlite"
    assert validate_database_url("data/app.db") == "sqlite"


def test_postgresql_database_url_requires_experimental_flag(monkeypatch):
    # Regression guard: unsupported database backends must not be silently accepted.
    monkeypatch.delenv("ODYSSEUS_EXPERIMENTAL_DATABASES", raising=False)
    with pytest.raises(DatabaseSupportError, match="unsupported"):
        validate_database_url("postgresql://localhost/odysseus")

    monkeypatch.setenv("ODYSSEUS_EXPERIMENTAL_DATABASES", "1")
    assert validate_database_url("postgresql://localhost/odysseus") == "postgresql"


def test_invalid_database_url_fails_clearly():
    # Regression guard: invalid config should fail with an actionable message.
    with pytest.raises(DatabaseSupportError, match="invalid"):
        validate_database_url("://bad")


def test_migration_from_old_fixture_succeeds_without_data_loss(tmp_path: Path):
    # Regression guard: sanitized old DB fixtures must preserve core rows.
    db = _old_db(tmp_path / "v0_1.sqlite")
    result = migrate_sqlite_database(db, backup_dir=tmp_path / "migration-backups")

    assert result.changed is True
    assert result.backup_path.exists()
    assert detect_schema_version(db) == 2
    assert _count(db, "users") == 1
    assert _count(db, "messages") == 1


def test_migration_is_idempotent(tmp_path: Path):
    # Regression guard: re-running migrations should not mutate data repeatedly.
    db = _old_db(tmp_path / "v0_2.sqlite")
    first = migrate_sqlite_database(db, backup_dir=tmp_path / "migration-backups")
    second = migrate_sqlite_database(db, backup_dir=tmp_path / "migration-backups")

    assert first.changed is True
    assert second.changed is False
    assert detect_schema_version(db) == 2
    assert _count(db, "users") == 1


def test_failed_migration_leaves_backup_and_does_not_advance_schema(tmp_path: Path):
    # Regression guard: partial migration failure must fail closed with backup intact.
    db = _old_db(tmp_path / "failing.sqlite")
    backup_dir = tmp_path / "migration-backups"

    with pytest.raises(MigrationError, match="simulated"):
        migrate_sqlite_database(db, backup_dir=backup_dir, fail_after_backup=True)

    assert list(backup_dir.glob("*.bak"))
    assert detect_schema_version(db) == 0
    assert _count(db, "users") == 1
