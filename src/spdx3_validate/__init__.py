# SPDX-FileCopyrightText: 2024 Joshua Watt
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: MIT
"""spdx3-validate: SPDX 3 validation library and CLI tool."""

from .main import spdx3validate
from .version import VERSION as __version__

__all__ = [
    "__version__",
    "spdx3validate",
]
