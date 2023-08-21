import pytest


def test_get_subcommand():
    """
    Run subcommand generator code for coverage.
    """
    conda_subcommands = pytest.importorskip(
        "conda_condent_trust.plugin.conda_subcommands"
    )
    assert len(list(conda_subcommands())) == 1
