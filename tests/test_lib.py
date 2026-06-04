# SPDX-FileContributor: Arthit Suriyawongkul
# SPDX-FileCopyrightText: 2026 Joshua Watt
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: MIT
"""Smoke tests."""

import re

import spdx3_validate


def test_public_api_is_importable():
    """Test that the public API is importable."""
    for name in spdx3_validate.__all__:
        assert hasattr(spdx3_validate, name), name


def test_spdx3validate_is_callable():
    """Test that spdx3validate is callable."""
    # No input files -> nothing to validate -> success (exit code 0)
    assert spdx3_validate.spdx3validate([]) == 0


def test_version_is_exposed():
    """Test that the version is exposed and looks like a version string."""
    assert isinstance(spdx3_validate.__version__, str)
    assert re.match(r"^\d+\.\d+\.\d+", spdx3_validate.__version__)
