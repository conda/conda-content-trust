# Copyright (C) 2019 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""
pytest-benchmark benchmarks for conda-content-trust.
"""
import datetime

import cryptography.exceptions
import pytest

from conda_content_trust.authentication import verify_signature
from conda_content_trust.common import (  # Putting this entire import list here as a sort of "to do" list
    PublicKey,
    checkformat_any_signature,
    checkformat_byteslike,
    checkformat_delegating_metadata,
    checkformat_delegation,
    checkformat_delegations,
    checkformat_expiration_distance,
    checkformat_gpg_signature,
    checkformat_hex_key,
    checkformat_hex_string,
    checkformat_list_of_hex_keys,
    checkformat_signature,
    checkformat_string,
)

from .test_authentication import (
    REG__MESSAGE_THAT_WAS_SIGNED,
    REG__PUBLIC_BYTES,
    REG__SIGNATURE_HEX,
    TEST_ROOT_MD_V1,
)
from .test_common import SAMPLE_GPG_SIG

SAMPLE_HEX_KEY_1 = "abcde123" * 8
SAMPLE_HEX_KEY_2 = "deadbeef" * 8


def bench_checkformat_hex_string():
    hex_string = "0123456789abcdef" * 4
    checkformat_hex_string(hex_string)


def test_benchmark_checkformat_hex_string(benchmark):
    benchmark(bench_checkformat_hex_string)


def verify_bad_signature():
    with pytest.raises(cryptography.exceptions.InvalidSignature):
        verify_signature(
            REG__SIGNATURE_HEX[:-6] + "ffffff",  # wrong value
            PublicKey.from_bytes(REG__PUBLIC_BYTES),
            REG__MESSAGE_THAT_WAS_SIGNED,
        )


def test_benchmark_verify_bad_signature(benchmark):
    # TODO create public key and actual signed data in a setup function
    # (creating the same public key repeatedly may be a big part of conda's
    # usage of conda-content-trust)
    benchmark(verify_bad_signature)


def verify_bad_signature_reuse_key(public_key):
    with pytest.raises(cryptography.exceptions.InvalidSignature):
        verify_signature(
            REG__SIGNATURE_HEX[:-6] + "ffffff",  # wrong value
            public_key,
            REG__MESSAGE_THAT_WAS_SIGNED,
        )


def test_benchmark_verify_bad_signature_reuse_key(benchmark):
    """
    Compare to test_benchmark_verify_bad_signature that recreates the PublicKey
    on each try.
    """
    benchmark(verify_bad_signature_reuse_key, PublicKey.from_bytes(REG__PUBLIC_BYTES))


def create_public_key_from_bytes():
    PublicKey.from_bytes(REG__PUBLIC_BYTES)


def test_benchmark_create_public_key(benchmark):
    benchmark(create_public_key_from_bytes)


def bench_checkformat_hex_key():
    checkformat_hex_key(SAMPLE_HEX_KEY_1)


def test_benchmark_checkformat_hex_key(benchmark):
    benchmark(bench_checkformat_hex_key)


def bench_checkformat_list_of_hex_keys():
    checkformat_list_of_hex_keys([SAMPLE_HEX_KEY_1, SAMPLE_HEX_KEY_2])


def test_benchmark_checkformat_list_of_hex_keys(benchmark):
    benchmark(bench_checkformat_list_of_hex_keys)


def bench_checkformat_any_signature():
    checkformat_any_signature(SAMPLE_GPG_SIG)


def test_bench_checkformat_any_signature(benchmark):
    benchmark(bench_checkformat_any_signature)


def bench_checkformat_byteslike():
    checkformat_byteslike(REG__PUBLIC_BYTES)


def test_benchmark_checkformat_byteslike(benchmark):
    benchmark(bench_checkformat_byteslike)


def benchmark_checkformat_gpg_signature():
    checkformat_gpg_signature(SAMPLE_GPG_SIG)


def test_benchmark_checkformat_gpg_signature(benchmark):
    benchmark(benchmark_checkformat_gpg_signature)


def benchmark_checkformat_signature():
    checkformat_signature(SAMPLE_GPG_SIG)


def test_benchmark_checkformat_signature(benchmark):
    benchmark(benchmark_checkformat_signature)


def benchmark_checkformat_string():
    checkformat_string(SAMPLE_HEX_KEY_1)


def test_benchmark_checkformat_string(benchmark):
    benchmark(benchmark_checkformat_string)


def benchmark_checkformat_delegation():
    checkformat_delegation(
        {
            "pubkeys": [SAMPLE_HEX_KEY_1, SAMPLE_HEX_KEY_2],
            "threshold": 1,
        }
    )


def test_benchmark_checkformat_delegation(benchmark):
    benchmark(benchmark_checkformat_delegation)


def benchmark_checkformat_delegations():
    checkformat_delegations(
        {
            "root.json": {"pubkeys": ["01" * 32, "02" * 32, "03" * 32], "threshold": 2},
            "test.json": {"pubkeys": ["04" * 32], "threshold": 1},
        }
    )


def test_benchmark_checkformat_delegations(benchmark):
    benchmark(benchmark_checkformat_delegations)


def benchmark_checkformat_delegating_metadata():
    checkformat_delegating_metadata(TEST_ROOT_MD_V1)


def test_benchmark_checkformat_delegating_metadata(benchmark):
    benchmark(benchmark_checkformat_delegating_metadata)


def benchmark_checkformat_expiration_distance():
    checkformat_expiration_distance(datetime.timedelta(days=100))


def test_benchmark_checkformat_expiration_distance(benchmark):
    benchmark(benchmark_checkformat_expiration_distance)
