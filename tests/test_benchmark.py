"""
pytest-benchmark benchmarks for conda-content-trust.
"""
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
)

SAMPLE_HEX_KEY = "abcde123" * 8


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
    checkformat_hex_key(SAMPLE_HEX_KEY)


def test_benchmark_checkformat_hex_key(benchmark):
    benchmark(bench_checkformat_hex_key)


def bench_checkformat_list_of_hex_keys():
    checkformat_list_of_hex_keys([SAMPLE_HEX_KEY, "deadbeef" * 8])


def test_benchmark_checkformat_list_of_hex_keys(benchmark):
    benchmark(bench_checkformat_list_of_hex_keys)


def bench_checkformat_any_signature():
    #     # What does a good placeholder ed25519 signature look like?
    private_key = "bfbeb6554fca9558da7aa05c5e9952b7a1aa3995dede93f3bb89f0abecc7dc07"
    #     private_key = cryptography.hazmat.primitives.asymmetric.ed25519
    #     public_key = "\x19t\x8e\xcb+\xebm\xa4\x99\xbew\x0f\xc1U\x19\xeb\xedn\xd8\xe9A \xc7o\x15\x96\x99\x83a\x8frU"
    checkformat_any_signature(REG__SIGNATURE_HEX)


#     # The error that I get here is:
#     # ValueError: Expected either a hex string representing a raw ed25519 signature
#     # (see checkformat_signature) or a dictionary representing an OpenPGP/GPG
#     # signature (see checkformat_gpg_signature).


@pytest.mark.skip
def test_bench_checkformat_any_signature(benchmark):
    benchmark(bench_checkformat_any_signature)
