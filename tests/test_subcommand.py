from conda_content_trust.plugin import conda_subcommands


def test_get_subcommand():
    """
    Run subcommand generator code for coverage.
    """
    assert len(list(conda_subcommands())) == 1
