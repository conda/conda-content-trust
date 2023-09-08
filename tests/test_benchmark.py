"""
pytest-benchmark benchmarks for conda-content-trust.
"""
from conda_content_trust.authentication import verify_signature
from conda_content_trust.common import (
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
    checkformat_signature,  # &&&&&& commented out test is there but not working
    checkformat_string,
)  # Putting this entire import list here as a sort of "to do" list


SAMPLE_HEX_KEY = "abcde123" * 8

def bench_checkformat_hex_string():
    hex_string = "0123456789abcdef" * 4
    checkformat_hex_string(hex_string)


def test_benchmark_checkformat_hex_string(benchmark):
    benchmark(bench_checkformat_hex_string)


def verify_bad_signature():
    signature = {}
    public_key = None
    data = {}
    verify_signature(signature, public_key, data)


def test_benchmark_verify_signature(benchmark):
    # TODO create public key and actual signed data in a setup function
    # (creating the same public key repeatedly may be a big part of conda's
    # usage of conda-content-trust)
    benchmark(verify_bad_signature)


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
    checkformat_any_signature(private_key)
#     # The error that I get here is:
#     # ValueError: Expected either a hex string representing a raw ed25519 signature
#     # (see checkformat_signature) or a dictionary representing an OpenPGP/GPG
#     # signature (see checkformat_gpg_signature).


def test_benchmark_checkformat_hex_key(benchmark):
    benchmark(bench_checkformat_any_signature)
