# Copyright (C) 2019 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""
Unit tests for conda-content-trust/conda_content_trust/signing.py

NOTE that much of the signing module is currently tested in
   test_authentication.py instead.  Some unit tests are missing.

Run the tests this way:
    pytest tests/test_signing.py
"""
import copy
import os
import os.path
import shutil

import pytest

from conda_content_trust.authentication import verify_signature
from conda_content_trust.common import (
    PublicKey,
    canonserialize,
    load_metadata_from_file,
)
from conda_content_trust.signing import sign_all_in_repodata, wrap_as_signable

# Some REGRESSION test data.
REG__KEYPAIR_NAME = "keytest_old"
REG__PRIVATE_BYTES = b"\xc9\xc2\x06\r~\r\x93al&T\x84\x0bI\x83\xd0\x02!\xd8\xb6\xb6\x9c\x85\x01\x07\xdat\xb4!h\xf97"
REG__PRIVATE_HEX = "c9c2060d7e0d93616c2654840b4983d00221d8b6b69c850107da74b42168f937"
REG__PUBLIC_BYTES = b"\x01=\xddqIb\x86m\x12\xba[\xae'?\x14\xd4\x8c\x89\xcf\x07s\xde\xe2\xdb\xf6\xd4V\x1eR\x1c\x83\xf7"
REG__PUBLIC_HEX = "013ddd714962866d12ba5bae273f14d48c89cf0773dee2dbf6d4561e521c83f7"
# Signature is over b'123456\x067890' using key REG__PRIVATE_BYTES.
REG__SIGNATURE = b'\xb6\xda\x14\xa1\xedU\x9e\xbf\x01\xb3\xa9\x18\xc9\xb8\xbd\xccFM@\x87\x99\xe8\x98\x84C\xe4}9;\xa4\xe5\xfd\xcf\xdaau\x04\xf5\xcc\xc0\xe7O\x0f\xf0F\x91\xd3\xb8"\x7fD\x1dO)*\x1f?\xd7&\xd6\xd3\x1f\r\x0e'
REG__HASHED_VAL = b"string to hash\n"
REG__HASH_HEX = "73aec9a93f4beb41a9bad14b9d1398f60e78ccefd97e4eb7d3cf26ba71dbe0ce"
# REG__HASH_BYTES = b's\xae\xc9\xa9?K\xebA\xa9\xba\xd1K\x9d\x13\x98\xf6\x0ex\xcc\xef\xd9~N\xb7\xd3\xcf&\xbaq\xdb\xe0\xce'
REG__REPODATA_HASHMAP = {
    "noarch/current_repodata.json": "908724926552827ab58dfc0bccba92426cec9f1f483883da3ff0d8664e18c0fe",
    "noarch/repodata.json": "908724926552827ab58dfc0bccba92426cec9f1f483883da3ff0d8664e18c0fe",
    "noarch/repodata_from_packages.json": "908724926552827ab58dfc0bccba92426cec9f1f483883da3ff0d8664e18c0fe",
    "osx-64/current_repodata.json": "8120fb07a6a8a280ffa2b89fb2fbb89484823d0b0357ff0cfa7c333352b2faa2",
    "osx-64/repodata.json": "8120fb07a6a8a280ffa2b89fb2fbb89484823d0b0357ff0cfa7c333352b2faa2",
    "osx-64/repodata_from_packages.json": "8120fb07a6a8a280ffa2b89fb2fbb89484823d0b0357ff0cfa7c333352b2faa2",
}
REG__TEST_TIMESTAMP = "2019-10-01T00:00:00Z"
REG__TEST_EXPIRY_DATE = "2025-01-01T10:30:00Z"
REG__EXPECTED_UNSIGNED_REPODATA_VERIFY = {
    "type": "repodata_verify",
    "timestamp": REG__TEST_TIMESTAMP,
    "metadata_spec_version": "0.1.0",
    "expiration": REG__TEST_EXPIRY_DATE,
    "secured_files": {
        "noarch/current_repodata.json": "908724926552827ab58dfc0bccba92426cec9f1f483883da3ff0d8664e18c0fe",
        "noarch/repodata.json": "908724926552827ab58dfc0bccba92426cec9f1f483883da3ff0d8664e18c0fe",
        "noarch/repodata_from_packages.json": "908724926552827ab58dfc0bccba92426cec9f1f483883da3ff0d8664e18c0fe",
        "osx-64/current_repodata.json": "8120fb07a6a8a280ffa2b89fb2fbb89484823d0b0357ff0cfa7c333352b2faa2",
        "osx-64/repodata.json": "8120fb07a6a8a280ffa2b89fb2fbb89484823d0b0357ff0cfa7c333352b2faa2",
        "osx-64/repodata_from_packages.json": "8120fb07a6a8a280ffa2b89fb2fbb89484823d0b0357ff0cfa7c333352b2faa2",
    },
}
REG__EXPECTED_REGSIGNED_REPODATA_VERIFY = {
    # Re-sign this if its data changes: it's signed!
    "type": "repodata_verify",
    "timestamp": "2019-10-01T00:00:00Z",
    "metadata_spec_version": "0.1.0",
    "expiration": "2025-01-01T10:30:00Z",
    "secured_files": {
        "noarch/current_repodata.json": "908724926552827ab58dfc0bccba92426cec9f1f483883da3ff0d8664e18c0fe",
        "noarch/repodata.json": "908724926552827ab58dfc0bccba92426cec9f1f483883da3ff0d8664e18c0fe",
        "noarch/repodata_from_packages.json": "908724926552827ab58dfc0bccba92426cec9f1f483883da3ff0d8664e18c0fe",
        "osx-64/current_repodata.json": "8120fb07a6a8a280ffa2b89fb2fbb89484823d0b0357ff0cfa7c333352b2faa2",
        "osx-64/repodata.json": "8120fb07a6a8a280ffa2b89fb2fbb89484823d0b0357ff0cfa7c333352b2faa2",
        "osx-64/repodata_from_packages.json": "8120fb07a6a8a280ffa2b89fb2fbb89484823d0b0357ff0cfa7c333352b2faa2",
    },
}
REG__REPODATA_SAMPLE_FNAME = "tests/testdata/repodata_sample.json"
REG__REPODATA_NO_PACKAGES_FNAME = "tests/testdata/repodata_no_packages.json"
REG__REPODATA_SAMPLE_TEMP_FNAME = "tests/repodata_sample_temp.json"


# def test_serialize_and_sign():
#     raise(NotImplementedError()
#             '⚠️ These tests are currently implemented in '
#             'test_authentication.py instead.'))

# def test_sign_signable():
#     raise(NotImplementedError(
#             '⚠️ These tests are currently implemented in '
#             'test_authentication.py instead.'))


def test_wrap_as_signable_default():
    obj = {"foo": "bar"}
    signed = wrap_as_signable(obj)
    assert signed == {"signatures": {}, "signed": obj}


def test_wrap_as_signable_error():
    with pytest.raises(TypeError):
        wrap_as_signable(object())


def remove_sample_tempfile():
    if os.path.exists(REG__REPODATA_SAMPLE_TEMP_FNAME):
        os.remove(REG__REPODATA_SAMPLE_TEMP_FNAME)


def test_sign_all_invalid_repodata(tmp_path):
    invalid_repodata = tmp_path / "invalid_repodata.json"
    invalid_repodata.write_text("{}")

    PublicKey.from_hex(REG__PUBLIC_HEX)

    # Make a test copy of the repodata sample, since we're going to
    # update it.
    if os.path.exists(REG__REPODATA_SAMPLE_TEMP_FNAME):
        os.remove(REG__REPODATA_SAMPLE_TEMP_FNAME)
    shutil.copy(REG__REPODATA_SAMPLE_FNAME, REG__REPODATA_SAMPLE_TEMP_FNAME)

    with pytest.raises(
        ValueError, match='Expected a "packages" entry in given repodata file.'
    ):
        sign_all_in_repodata(str(invalid_repodata), REG__PRIVATE_HEX)


def test_sign_all_in_repodata(request):
    request.addfinalizer(remove_sample_tempfile)

    public = PublicKey.from_hex(REG__PUBLIC_HEX)

    # Make a test copy of the repodata sample, since we're going to
    # update it.
    if os.path.exists(REG__REPODATA_SAMPLE_TEMP_FNAME):
        os.remove(REG__REPODATA_SAMPLE_TEMP_FNAME)
    shutil.copy(REG__REPODATA_SAMPLE_FNAME, REG__REPODATA_SAMPLE_TEMP_FNAME)

    # grab data and use it to compare to what we produce in a bit

    repodata = load_metadata_from_file(REG__REPODATA_SAMPLE_FNAME)

    sign_all_in_repodata(REG__REPODATA_SAMPLE_TEMP_FNAME, REG__PRIVATE_HEX)

    repodata_signed = load_metadata_from_file(REG__REPODATA_SAMPLE_TEMP_FNAME)

    # Ensure that the rest of repodata is unchanged.
    repodata_signed_stripped = copy.deepcopy(repodata_signed)
    del repodata_signed_stripped["signatures"]
    assert repodata_signed_stripped == repodata
    del repodata_signed_stripped

    # Make sure there is one signature entry for every artifact entry, and no
    # mystery entries.
    assert set(repodata["packages"].keys()) | set(
        repodata["packages.conda"].keys()
    ) == set(repodata_signed["signatures"].keys())

    for artifact_name in repodata["packages"]:
        # There's a signature "by" this key listed for every artifact.
        assert REG__PUBLIC_HEX in repodata_signed["signatures"][artifact_name]
        # The signature is valid.
        verify_signature(
            # signature, (supposed) key, data that was (supposedly) signed
            repodata_signed["signatures"][artifact_name][REG__PUBLIC_HEX]["signature"],
            public,
            canonserialize(repodata["packages"][artifact_name]),
        )


def test_wrap_unserializable():
    with pytest.raises(TypeError):
        wrap_as_signable(object())


def test_sign_all_in_repodata_no_packages(request):
    request.addfinalizer(remove_sample_tempfile)

    # Make a test copy of the repodata sample, since we're going to
    # update it.
    if os.path.exists(REG__REPODATA_SAMPLE_TEMP_FNAME):
        os.remove(REG__REPODATA_SAMPLE_TEMP_FNAME)
    shutil.copy(REG__REPODATA_NO_PACKAGES_FNAME, REG__REPODATA_SAMPLE_TEMP_FNAME)

    with pytest.raises(ValueError):
        sign_all_in_repodata(REG__REPODATA_SAMPLE_TEMP_FNAME, REG__PRIVATE_HEX)
