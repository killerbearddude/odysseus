"""
Admin diagnostics API route for Odysseus.

The endpoint is intentionally read-only and admin-gated. It returns the same
redacted diagnostics structure used by local support bundles, without exposing
raw logs, private documents, uploaded files, prompts, or secrets.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from core.security_dependencies import require_admin
from services.diagnostics import collect_diagnostics


def setup_admin_diagnostics_routes() -> APIRouter:
    """
    Build the admin diagnostics router.

    Returns:
        APIRouter exposing ``GET /api/admin/diagnostics`` behind the existing
        admin authorization dependency.
    """
    router = APIRouter(
        prefix="/api/admin",
        tags=["admin", "diagnostics"],
        dependencies=[Depends(require_admin)],
    )

    @router.get("/diagnostics")
    def get_admin_diagnostics() -> dict:
        """Return a redacted, read-only diagnostics snapshot."""
        return collect_diagnostics()

    return router


router = setup_admin_diagnostics_routes()
