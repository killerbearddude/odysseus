"""
Small SQLite migration discipline helpers for Odysseus alpha.

The helpers exercise the expected migration contract: detect schema version,
create a pre-migration backup, apply changes in a transaction, verify the final
version, and fail closed without silently advancing schema state on errors.
"""

from __future__ import annotations

import shutil
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


SCHEMA_VERSION_TABLE = "odysseus_schema_version"
TARGET_SCHEMA_VERSION = 2


class MigrationError(RuntimeError):
    """Raised when a migration cannot complete safely."""


@dataclass(frozen=True)
class MigrationResult:
    """Summary of a completed migration run."""

    database_path: Path
    from_version: int
    to_version: int
    backup_path: Path
    changed: bool


def detect_schema_version(database_path: Path) -> int:
    """Return the current SQLite schema version, defaulting old DBs to zero."""
    database_path = Path(database_path)
    if not database_path.exists():
        return 0
    with sqlite3.connect(database_path) as conn:
        exists = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (SCHEMA_VERSION_TABLE,),
        ).fetchone()
        if not exists:
            return 0
        row = conn.execute(f"SELECT version FROM {SCHEMA_VERSION_TABLE} LIMIT 1").fetchone()
        return int(row[0]) if row else 0


def create_pre_migration_backup(database_path: Path, backup_dir: Path) -> Path:
    """Copy the database file before migration and return the backup path."""
    database_path = Path(database_path)
    backup_dir = Path(backup_dir)
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = backup_dir / f"{database_path.name}.pre-migration-{stamp}.bak"
    if database_path.exists():
        shutil.copy2(database_path, backup_path)
    else:
        backup_path.write_bytes(b"")
    return backup_path


def _table_count(conn: sqlite3.Connection, table_name: str) -> int | None:
    """Return a table row count, or ``None`` when the table does not exist."""
    exists = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    if not exists:
        return None
    return int(conn.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0])


def _core_counts(conn: sqlite3.Connection) -> dict[str, int | None]:
    """Collect row counts for core tables used by migration regression tests."""
    return {table: _table_count(conn, table) for table in ("users", "sessions", "messages", "documents", "scheduled_tasks")}


def migrate_sqlite_database(
    database_path: Path,
    *,
    target_version: int = TARGET_SCHEMA_VERSION,
    backup_dir: Path | None = None,
    fail_after_backup: bool = False,
) -> MigrationResult:
    """
    Migrate a SQLite database to the requested schema version.

    The current implementation creates/updates a central schema-version table
    and preserves existing core-table row counts. ``fail_after_backup`` is a
    test hook that proves pre-migration backups remain available and schema
    state is not advanced after a failure.
    """
    database_path = Path(database_path)
    backup_dir = Path(backup_dir) if backup_dir is not None else database_path.parent / "migration-backups"
    from_version = detect_schema_version(database_path)
    backup_path = create_pre_migration_backup(database_path, backup_dir)

    if fail_after_backup:
        raise MigrationError("simulated migration failure after pre-migration backup")

    if from_version >= target_version:
        return MigrationResult(database_path, from_version, from_version, backup_path, changed=False)

    try:
        conn = sqlite3.connect(database_path)
        try:
            conn.isolation_level = None
            conn.execute("BEGIN")
            before_counts = _core_counts(conn)
            conn.execute(
                f"CREATE TABLE IF NOT EXISTS {SCHEMA_VERSION_TABLE} "
                "(version INTEGER NOT NULL, updated_at TEXT NOT NULL)"
            )
            conn.execute(f"DELETE FROM {SCHEMA_VERSION_TABLE}")
            conn.execute(
                f"INSERT INTO {SCHEMA_VERSION_TABLE} (version, updated_at) VALUES (?, ?)",
                (target_version, datetime.now(timezone.utc).isoformat()),
            )
            after_counts = _core_counts(conn)
            if before_counts != after_counts:
                raise MigrationError("core table row counts changed during migration")
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
    except MigrationError:
        raise
    except Exception as exc:
        raise MigrationError(f"SQLite migration failed: {exc}") from exc

    final_version = detect_schema_version(database_path)
    if final_version != target_version:
        raise MigrationError("migration completed without reaching target schema version")

    return MigrationResult(database_path, from_version, final_version, backup_path, changed=True)
