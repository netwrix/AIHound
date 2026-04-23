"""Tests for permissions module."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from aihound.core.permissions import assess_risk
from aihound.core.scanner import RiskLevel, StorageType


def test_plaintext_file_not_info():
    """PLAINTEXT_FILE should be treated as plaintext, not fall through to INFO."""
    risk = assess_risk(StorageType.PLAINTEXT_FILE)
    assert risk != RiskLevel.INFO, (
        "PLAINTEXT_FILE fell through to INFO — it should be HIGH like other plaintext types"
    )


def test_plaintext_file_is_high_without_path():
    """Without a path to check permissions, PLAINTEXT_FILE defaults to HIGH."""
    risk = assess_risk(StorageType.PLAINTEXT_FILE)
    assert risk == RiskLevel.HIGH
