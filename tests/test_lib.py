# SPDX-FileContributor: Arthit Suriyawongkul
# SPDX-FileCopyrightText: 2026 Joshua Watt
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: MIT
"""Test spdx3-validate as a library."""

import re
import urllib.error
from pathlib import Path

import pytest

import spdx3_validate

FIXTURES = Path(__file__).parent / "fixtures"


def test_public_api_is_importable():
    """Test that the public API is importable."""
    for name in spdx3_validate.__all__:
        assert hasattr(spdx3_validate, name), name


def test_spdx3validate_is_callable():
    """Test that spdx3validate is callable."""
    # No input files -> nothing to validate -> success (exit code 0)
    assert spdx3_validate.spdx3validate([]) == 0


def test_spdx3validate_valid_document():
    """A known-valid SPDX 3.0.1 document validates successfully."""
    doc_path = FIXTURES / "v3_0_1" / "valid" / "package_sbom.json"
    try:
        rc = spdx3_validate.spdx3validate([str(doc_path)])
    except urllib.error.URLError as e:
        pytest.skip(f"network unavailable: {e}")
    assert rc == 0


def test_version_is_exposed():
    """Test that the version is exposed and looks like a version string."""
    assert isinstance(spdx3_validate.__version__, str)
    assert re.match(r"^\d+\.\d+\.\d+", spdx3_validate.__version__)
