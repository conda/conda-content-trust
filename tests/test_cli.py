# Copyright (C) 2019 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
from __future__ import annotations

import pytest
import sys

from conda_content_trust.cli import cli


@pytest.mark.parametrize(
    "args",
    [
        ["-V"],
        ["--version"],
        ["--help"],
    ],
)
def test_cli_basic(args: list[str]):
    with pytest.raises(SystemExit):
        cli(args)


@pytest.mark.parametrize(
    "trusted,untrusted",
    [
        ["tests/testdata/1.root.json", "tests/testdata/2.root.json"],
        ["tests/testdata/1.root.json", "tests/testdata/key_mgr.json"],
    ],
)
def test_cli_verify_metadata(trusted: str, untrusted: str):
    err = cli(["verify-metadata", trusted, untrusted])
    assert not err


def test_main(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["conda-content-trust"])
    __import__("conda_content_trust.__main__")
