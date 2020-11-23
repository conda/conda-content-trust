# -*- coding: utf-8 -*-

""" tests.test_cli

Integration tests for conda-authentication-resources/car/cli.py.

Run the tests this way:
    pytest tests/test_cli.py

"""

import subprocess

import car.cli

def test_cli_basics():
  assert not subprocess.call(['car', '-V'])
  assert not subprocess.call(['car', '--version'])
  assert not subprocess.call(['car', '--help'])

def test_that_all_calls_complete():
  assert not subprocess.call(['car', '-V'])
  assert not subprocess.call(['car', '--version'])
  assert not subprocess.call(['car', '--help'])

def test_gpg_key_fingerprint():
  assert not subprocess.call(['car', '-V'])
  raise NotImplementedError()

def test_():
  raise NotImplementedError()

def test_():
  raise NotImplementedError()

def test_():
  raise NotImplementedError()

def test_():
  raise NotImplementedError()

def test_():
  raise NotImplementedError()

def test_():
  raise NotImplementedError()

def test_():
  raise NotImplementedError()

