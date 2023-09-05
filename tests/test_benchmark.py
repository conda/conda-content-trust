"""
pytest-benchmark benchmarks for conda-content-trust.
"""
from conda_content_trust.authentication import verify_signature
from conda_content_trust.common import checkformat_hex_string


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
