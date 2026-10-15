# SPDX-FileContributor: Joshua Watt
# SPDX-FileCopyrightText: 2024 Joshua Watt
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: MIT
"""spdx3-validate: SPDX 3 validation library and CLI tool."""

from .core import (
    Document,
    ResourceNotFoundError,
    SpdxValidateError,
    UnknownVersionError,
    ValidationError,
    ValidationResult,
    PreReleaseWarning,
    Validator,
    validate,
)
from .main import spdx3validate
from .version import VERSION as __version__

__all__ = [
    "Document",
    "ResourceNotFoundError",
    "SpdxValidateError",
    "UnknownVersionError",
    "ValidationError",
    "ValidationResult",
    "PreReleaseWarning",
    "Validator",
    "__version__",
    "spdx3validate",
    "validate",
]
