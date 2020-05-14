# -*- coding: utf-8 -*-

""" tests.test_cli

Integration tests for conda-authentication-resources/car/cli.py.

Run the tests this way:
    pytest tests/test_cli.py

"""

from car import cli

def test_cli_template():
    assert cli.cli() is None
