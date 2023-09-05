"""
pytest-benchmark benchmarks for conda-content-trust.
"""
from conda_content_trust.common import checkformat_hex_string


def bench_checkformat_hex_string():
    hex_string = "0123456789abcdef" * 4
    checkformat_hex_string(hex_string)


def test_benchmark_checkformat_hex_string(benchmark):
    benchmark(bench_checkformat_hex_string)
