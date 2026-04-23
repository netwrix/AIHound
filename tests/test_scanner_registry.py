"""Regression guard for the scanner-registration pipeline.

Prevents the "got fewer scanners than expected" class of bug — e.g., a stale
Python install on PYTHONPATH masking new scanners, or a scanner module silently
failing to import and getting dropped from the registry.

If a new scanner is added to `aihound/scanners/`, this test passes once that
file is properly importable and `@register`-decorated. If a scanner file exists
but doesn't end up in the registry (broken `@register`, ImportError, etc.),
this test fails loudly.
"""

from __future__ import annotations

from pathlib import Path

import aihound.scanners as scanners_pkg
from aihound.scanners import get_all_scanners


def _scanner_module_files() -> list[str]:
    """Names of every Python module under aihound/scanners/ except __init__.py."""
    pkg_dir = Path(scanners_pkg.__file__).parent
    return sorted(
        p.stem
        for p in pkg_dir.glob("*.py")
        if p.stem != "__init__"
    )


def test_every_scanner_file_is_registered():
    """Every .py file in aihound/scanners/ must register at least one scanner."""
    module_files = _scanner_module_files()
    registered = get_all_scanners()
    assert len(registered) >= len(module_files), (
        f"Found {len(module_files)} scanner module files on disk "
        f"({module_files}) but only {len(registered)} scanners registered "
        f"({sorted(s.slug() for s in registered)}). "
        f"Likely cause: a scanner file exists but its @register decorator "
        f"didn't fire (ImportError or missing decorator)."
    )


def test_registered_scanner_count_is_at_least_28():
    """Anchor: ensure no future change silently drops scanners below expected count.

    If a scanner is intentionally removed, bump this number AND update the docs.
    Failure here means scanners regressed (silent ImportError, removed file,
    etc.) and end users would suddenly get less coverage.
    """
    registered = get_all_scanners()
    assert len(registered) >= 28, (
        f"Expected >=28 registered scanners (v3.0.0 + shell/env scanners), got "
        f"{len(registered)}: {sorted(s.slug() for s in registered)}"
    )


def test_scanner_slugs_are_unique():
    """Two scanners with the same slug would silently collide in --tools filtering."""
    slugs = [s.slug() for s in get_all_scanners()]
    duplicates = sorted({s for s in slugs if slugs.count(s) > 1})
    assert not duplicates, f"Duplicate scanner slugs found: {duplicates}"
