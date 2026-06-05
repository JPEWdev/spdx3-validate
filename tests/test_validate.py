# SPDX-FileContributor: Arthit Suriyawongkul
# SPDX-FileCopyrightText: 2026 Joshua Watt
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: MIT
"""Test spdx3validate function."""

import urllib.error
from pathlib import Path

import pytest

import spdx3_validate

DATA_DIR = Path(__file__).parent / "data"


def test_spdx3validate_is_callable():
    """Test that spdx3validate is callable."""
    # No input files -> nothing to validate -> success (exit code 0)
    assert spdx3_validate.spdx3validate([]) == 0


def test_spdx3validate_invalid():
    """A known-invalid SPDX 3.0.1 document fails validation."""
    doc_path = DATA_DIR / "3.0.1" / "invalid" / "package_sbom_missing_creationinfo.json"
    try:
        rc = spdx3_validate.spdx3validate([str(doc_path)])
    except urllib.error.URLError as e:
        pytest.skip(f"network unavailable: {e}")
    assert rc != 0


def test_spdx3validate_valid():
    """A known-valid SPDX 3.0.1 document validates successfully."""
    doc_path = DATA_DIR / "3.0.1" / "valid" / "package_sbom.json"
    try:
        rc = spdx3_validate.spdx3validate([str(doc_path)])
    except urllib.error.URLError as e:
        pytest.skip(f"network unavailable: {e}")
    assert rc == 0

