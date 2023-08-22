# Copyright (C) 2019 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""Placeholder for the actual version code injected by hatch-vcs.
"""
try:  # pragma: no cover
    from setuptools_scm import get_version

    __version__ = get_version(root="..", relative_to=__file__)
except (ImportError, OSError):  # pragma: no cover
    # ImportError: setuptools_scm isn't installed
    # OSError: git isn't installed
    __version__ = "0.0.0.dev0+placeholder"
