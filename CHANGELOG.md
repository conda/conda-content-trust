[//]: # (current developments)

## 0.3.1 (2026-04-01)

### Bug fixes

* Fix `conda.plugins` import. (#260)

### Contributors

* @jezdez
* @kenodegard



## 0.3.0 (2026-03-18)

### Enhancements

* Add support for Python 3.13. (#239)
* Add `CondaPostSolve` plugin hook for signature verification, migrated from `conda.trust.signature_verification`. This enables automatic package signature verification when conda's `extra_safety_checks` is enabled and a trust root is installed (e.g., via `conda-anaconda-trust-root`). (#245)
* Add `verification` module with `_SignatureVerification` class for verifying package metadata signatures during conda's solve phase. (#245)
* Add `constants` module with `KEY_MGR_FILE` constant, migrated from `conda.trust.constants`. (#245)
* Add support for Python 3.14. (#245)

### Deprecations

* Drop support for Python 3.8 and 3.9. (#239)

### Other

* Use `bytes.hex()` APIs instead of `binascii.unhexlify()` (#81)
* Increase test coverage. Refactor cli to be more testable. (#96)
* Remove flake8 ignores and fix findings or add `# noqa` inline. (#98)

### Contributors

* @agriyakhetarpal made their first contribution in https://github.com/conda/conda-content-trust/pull/238
* @beeankha
* @conda-bot
* @dbast made their first contribution in https://github.com/conda/conda-content-trust/pull/98
* @dholth
* @jaimergp made their first contribution in https://github.com/conda/conda-content-trust/pull/227
* @jezdez
* @kenodegard
* @dependabot[bot]
* @pre-commit-ci[bot]

## 0.2.0 (2023-08-29)

### Enhancements

* Improve compatibility with `cryptography>=41`. (#56)
* Convert `setup.py`/`setuptools` build backend to `pyproject.toml`/`hatchling`. (#62)
* Add canary builds. (#68)

### Deprecations

* Drop Python 2 support. (#37)
* Remove unused `conda_content_trust.encryption`. (#38)

### Other

* Enable pre-commit for linting and auto-formatting. (#35)
* Replace `darker` with `black` pre-commit hook. (#58)
* Add `isort` pre-commit hook. (#58)
* Increase test coverage. (#69, #71, #72, #75)
* Increase test coverage by removing unreachable/unused code. (#72, #74)

### Contributors

* @beeankha made their first contribution in https://github.com/conda/conda-content-trust/pull/75
* @conda-bot
* @dholth made their first contribution in https://github.com/conda/conda-content-trust/pull/74
* @jezdez made their first contribution in https://github.com/conda/conda-content-trust/pull/6
* @kenodegard made their first contribution in https://github.com/conda/conda-content-trust/pull/12
* @awwad
* @dependabot[bot] made their first contribution in https://github.com/conda/conda-content-trust/pull/17
* @pre-commit-ci[bot] made their first contribution in https://github.com/conda/conda-content-trust/pull/73
