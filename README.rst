.. image:: https://img.shields.io/travis/conda/conda-authentication-resources.svg
        :target: https://travis-ci.org/conda/conda-authentication-resources
.. image:: https://circleci.com/gh/conda/conda-authentication-resources.svg?style=svg
    :target: https://circleci.com/gh/conda/conda-authentication-resources
.. image:: https://codecov.io/gh/conda/conda-authentication-resources/branch/master/graph/badge.svg
   :target: https://codecov.io/gh/conda/conda-authentication-resources


##############################################################################
Conda Content Trust: Signing and verification tools for Conda
##############################################################################


**************
Installation
**************

Installation can be accomplished by:

1. obtaining this code (download a zip and expand it or git clone the repository). e.g.:
    ``git clone https://github.com/conda/conda-content-trust``

2. ``cd conda-content-trust``

3. ``pip install .``

If you intend to tinker with the code, use an editable install instead:
``pip install -e .``

========================================================================
Optional Dependencies for Producing Signatures with GPG Keys / YubiKeys
========================================================================

If you intend to *create* *GPG* key signatures (as opposed to the typical non-GPG signatures), and/or you intend to use the YubiKey interface, you will need to install two optional dependencies:
- GPG (any gpg client that provides command-line gpg functionality should do)
- `securesystemslib` (`pip install securesystemslib`)


*********************
Demonstration and Use
*********************

Use of the command-line utility provides help functionality::
  ``conda-content-trust --help``

You should be able to run the demo after installing:
  ``python3 demo.py``
(Portions of the demo may require the optional dependencies above.)


*******************
Testing
*******************

Each set of tests is a module in the ``tests/`` directory.  These can each be run with pytest.  For example:
  ``pytest tests/test_authentication.py``
