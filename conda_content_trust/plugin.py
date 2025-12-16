# Copyright (C) 2019 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause

from conda import __version__ as conda_version

from .cli import cli

version_parts = conda_version.split('.')
major = int(version_parts[0]) # year
minor = int(version_parts[1]) if len(version_parts) > 1 else 0 # month

if (major, minor) >= (25, 9):
    from conda.plugins.types import CondaSubcommand
else:
    from conda.plugins import CondaSubcommand


@conda.plugins.hookimpl
def conda_subcommands():
    yield CondaSubcommand(
        name="content-trust",
        summary="Signing and verification tools for Conda",
        action=cli,
    )
