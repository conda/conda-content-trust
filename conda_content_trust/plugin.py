# Copyright (C) 2019 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
import conda.plugins.types

from .cli import cli


@conda.plugins.hookimpl
def conda_subcommands():
    yield conda.plugins.types.CondaSubcommand(
        name="content-trust",
        summary="Signing and verification tools for Conda",
        action=cli,
    )
