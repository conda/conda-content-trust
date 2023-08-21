import pytest


def test_get_subcommand():
    """
    Run subcommand generator code for coverage.
    """
    try:
        from conda_content_trust.plugin import conda_subcommands
    except ImportError:
        pytest.skip("could not import plugin.conda_subcommands")
    assert len(list(conda_subcommands())) == 1
