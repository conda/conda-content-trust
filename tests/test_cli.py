# -*- coding: utf-8 -*-
# Copyright (C) 2019 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""
Integration tests for conda-content-trust/conda_content_trust/cli.py.

Run the tests this way:
    pytest tests/test_cli.py
"""
import subprocess


def test_cli_basics():
  assert not subprocess.call(['conda-content-trust', '-V'])
  assert not subprocess.call(['conda-content-trust', '--version'])
  assert not subprocess.call(['conda-content-trust', '--help'])

def test_that_all_calls_complete():
  assert not subprocess.call([
      'conda-content-trust', 'verify-metadata',
      'tests/testdata/1.root.json', 'tests/testdata/2.root.json'])
  assert not subprocess.call([
      'conda-content-trust', 'verify-metadata',
      'tests/testdata/1.root.json', 'tests/testdata/key_mgr.json'])



# def test_gpg_key_fingerprint():
#   raise NotImplementedError()

# def test_():
#   raise NotImplementedError()

# def test_():
#   raise NotImplementedError()

# def test_():
#   raise NotImplementedError()

# def test_():
#   raise NotImplementedError()

# def test_():
#   raise NotImplementedError()

# def test_():
#   raise NotImplementedError()

# def test_():
#   raise NotImplementedError()
