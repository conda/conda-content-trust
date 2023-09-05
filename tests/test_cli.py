# Copyright (C) 2019 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
from __future__ import annotations

import pytest
import sys
import conda_content_trust.signing
import conda_content_trust.root_signing
from conda_content_trust.cli import (
    cli,
    build_parser,
    cli_sign_artifacts,
    cli_gpg_key_lookup,
    cli_gpg_sign,
    cli_modify_metadata,
    cli_verify_metadata,
)


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
    "trusted,untrusted,expected_error",
    [
        ["tests/testdata/1.root.json", "tests/testdata/2.root.json", False],
        ["tests/testdata/1.root.json", "tests/testdata/key_mgr.json", False],
        ["tests/testdata/1.root.json", "tests/testdata/3.root.json", True],
    ],
)
def test_cli_verify_metadata(trusted: str, untrusted: str, expected_error: bool):
    err = cli(["verify-metadata", trusted, untrusted])
    assert bool(err) == expected_error


def test_main(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["conda-content-trust"])
    __import__("conda_content_trust.__main__")


def test_cli_no_securesystemslib(monkeypatch):
    monkeypatch.setattr(conda_content_trust.root_signing, "SSLIB_AVAILABLE", False)
    cli([])


def test_cli_build_parser():
    """
    Check that parser assigns correct functions to subcommands.
    """
    parser = build_parser()
    args_expected = [
        (["sign-artifacts", "file1", "file2"], cli_sign_artifacts),
        (["verify-metadata", "file1", "file2"], cli_verify_metadata),
        (["modify-metadata", "file1"], cli_modify_metadata),
        (["gpg-key-lookup", "fingerprint"], cli_gpg_key_lookup),
        (["gpg-sign", "fingerprint", "file1"], cli_gpg_sign),
        ([], None),
    ]
    for args, expected in args_expected:
        parsed = parser.parse_args(args)
        assert getattr(parsed, "func", None) == expected


def test_cli_gpg_sign(monkeypatch):
    def mock(*args):
        pass

    monkeypatch.setattr(
        conda_content_trust.root_signing, "sign_root_metadata_via_gpg", mock
    )
    cli(["gpg-sign", "file1", "file2"])


def test_cli_sign_artifacts(monkeypatch, tmp_path):
    def mock(*args):
        pass

    def fail_if_called(*args):
        assert False

    hex_key = tmp_path / "key.hex"

    hex_key.write_text("Invalid Key")
    monkeypatch.setattr(
        conda_content_trust.signing, "sign_all_in_repodata", fail_if_called
    )
    cli(["sign-artifacts", "repodata-filename", str(hex_key)])

    monkeypatch.setattr(conda_content_trust.signing, "sign_all_in_repodata", mock)
    hex_key.write_text("a" * 64)
    cli(["sign-artifacts", "repodata-filename", str(hex_key)])


def test_cli_gpg_key_lookup(monkeypatch):
    def mock(*args):
        pass

    monkeypatch.setattr(conda_content_trust.root_signing, "fetch_keyval_from_gpg", mock)
    cli(["gpg-key-lookup", "fingerprint"])


# TODO Difficult to test this interactive command
# def test_cli_modify_metadata():
#     pass


# def test_cli_verify_metadata(monkeypatch):
#     def verify_delegation_succeed(*args, **kwargs):
#         pass

#     def verify_delegation_fail(*args, **kwargs):
#         raise CCT_Error()

#     cli(["verify-metadata", "tests/testdata/1.root.json", "tests/testdata/2.root.json"])