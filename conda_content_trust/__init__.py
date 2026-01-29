# Copyright (C) 2019 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""Conda content trust - signing and verification tools for Conda.

This package provides cryptographic signing and verification functionality
for conda packages and metadata, based on The Update Framework (TUF).
"""

from .__version__ import __version__  # noqa: F401

# Public API exports
from .constants import KEY_MGR_FILE  # noqa: F401
from .verification import signature_verification  # noqa: F401
