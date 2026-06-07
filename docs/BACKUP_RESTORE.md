# Odysseus Backup, Restore, and Migration Discipline

## Scope

SQLite is the supported database for the Odysseus alpha hardening baseline. Other database backends are experimental and must not be treated as production-supported without an explicit operator opt-in and dedicated migration tests.

The backup/restore process is local-first and human-triggered. It is intended to protect a small-team or solo-operator installation from data loss before migrations, imports, generated-artifact changes, model/index changes, or destructive maintenance.

## What must be backed up

Back up these items when present:

- `data/app.db` - primary SQLite application database.
- Auth/session files - login, setup, and session state must stay paired with the database where applicable.
- `uploads/` - user-uploaded files and metadata references.
- `generated/` - generated media and artifacts referenced by the app.
- Documents and import storage - source material used by document ingestion or retrieval workflows.
- ChromaDB volume - vector index state, when configured.
- SearXNG config volume - local search configuration, when configured.
- ntfy volume - notification service state, when configured.
- `.app_key` - application key material. Restore this with the database it belongs to.
- `.env` - deployment configuration. Never publish it and never commit it.
- Provider settings - model/provider configuration references.
- Model cache - local model files and metadata when they are not reproducible or are expensive to recreate.
- Cookbook-installed packages - package state installed outside normal dependency management.
- Tool audit database, if present - usually `data/tool_audit.sqlite`.
- Staging/review packets, if present - usually under `data/staging/`.

## Restore warnings

Before restoring:

1. Stop Odysseus and any background workers.
2. Take a fresh backup before overwriting existing data.
3. Verify the archive before restore.
4. Restore `.app_key` with the database it belongs to.
5. Never publish backup archives.
6. Never commit backup archives.
7. Inspect warnings about missing `.app_key` or `.env` before proceeding.

## CLI usage

Create a backup:

```bash
scripts/odysseus-backup create ./backups/odysseus-$(date +%F).tar.zst
```

Verify a backup:

```bash
scripts/odysseus-backup verify ./backups/odysseus-2026-06-07.tar.zst
```

Restore a backup after human confirmation:

```bash
scripts/odysseus-backup restore ./backups/odysseus-2026-06-07.tar.zst --yes
```

The restore command creates a pre-restore safety snapshot under `backups/` before writing restored files.

## Backup manifest

Each archive includes `BACKUP_MANIFEST.json`. The manifest records operational metadata such as creation time, app commit, included paths, excluded paths, Python version, host platform, and whether key files were present.

The manifest must not contain raw secret values.

## Archive safety rules

Restore verification rejects archives containing:

- absolute paths
- `../` traversal paths
- symlinks
- hardlinks
- device files
- FIFOs
- unexpected top-level layouts

Bad archives must be rejected before any live file is written.

## Migration discipline

Migration flow should follow this pattern:

1. Detect schema version.
2. Create a pre-migration backup.
3. Begin a transaction.
4. Apply the migration.
5. Verify target schema version.
6. Verify core row-count or data-integrity invariants.
7. Commit.
8. On failure, roll back and keep the pre-migration backup.

Destructive migrations require:

- documented reason
- pre-migration backup
- fixture proving no unintended data loss
- rollback note in the PR or migration comment

Startup should fail clearly on partial migration failure rather than advancing schema state silently.

## Database support boundary

Supported by default:

- filesystem SQLite path
- `sqlite:///...`
- default local SQLite configuration

Unsupported unless explicitly experimental:

- PostgreSQL
- MySQL/MariaDB
- other SQLAlchemy backends

Set `ODYSSEUS_EXPERIMENTAL_DATABASES=1` only for explicit experimental testing of non-SQLite backends. This does not make those backends production-supported.
