"""
Pytest collection policy for Odysseus CI marker jobs.

The repository has a large legacy test suite that predates explicit pytest
markers. This file keeps CI marker jobs useful while tests are migrated:
security-path tests are marked as security, and otherwise-unmarked tests are
treated as unit tests by default.
"""

from __future__ import annotations

from pathlib import Path

import pytest


# Markers controlled by this policy. Tests that already declare one of these
# markers keep their explicit classification.
_CI_MARKERS = {"unit", "security", "integration", "docker", "slow"}


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """
    Assign default CI markers during test collection.

    Security tests live under ``tests/security`` and should always run in the
    dedicated security CI job. Legacy tests without explicit CI markers are
    marked as unit tests so ``pytest -m unit`` remains a meaningful blocking job
    instead of selecting zero tests.
    """
    for item in items:
        marker_names = {marker.name for marker in item.iter_markers()}
        if marker_names & _CI_MARKERS:
            continue

        test_path = Path(str(item.fspath))
        if "tests/security" in test_path.as_posix():
            item.add_marker(pytest.mark.security)
        else:
            item.add_marker(pytest.mark.unit)
