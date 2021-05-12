
##############################################################################
Conda Content Trust: Signing and verification tools for Conda
##############################################################################

Based on `The Update Framework (TUF)<https://theupdateframework.io/>`_, conda-content-trust is intended to ensure that when users in the conda ecosystem obtain a package or data about that package, they can know whether or not it is trustworthy (e.g. originally comes from a reliable source and has not been tampered with).  It is used in conda 4.10.1+ to verify package metadata signatures when they are available.  A basic library and basic CLI are included to provide signing, verification, and trust delegation functionality.

**************
Installation
**************

Installation can be accomplished via conda:
  ``conda install conda-content-trust``

Or via pip:
  ``git clone https://github.com/conda/conda-content-trust
  cd conda-content-trust
  pip install .``

(If you intend to tinker with the code, use an editable install instead, of course: ``pip install -e .``)

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
