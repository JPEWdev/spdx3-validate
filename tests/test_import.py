# SPDX-FileContributor: Arthit Suriyawongkul
# SPDX-FileCopyrightText: 2026 Joshua Watt
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: MIT
"""Test import."""

import re

import spdx3_validate


def test_public_api_is_importable() -> None:
    """Test that the public API is importable."""
    for name in spdx3_validate.__all__:
        assert hasattr(spdx3_validate, name), name


def test_version_is_exposed() -> None:
    """Test that the version is exposed and looks like a version string."""
    assert isinstance(spdx3_validate.__version__, str)
    assert re.match(r"^\d+\.\d+\.\d+", spdx3_validate.__version__)
