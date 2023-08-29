[//]: # (current developments)

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

* @beeankha
* @conda-bot
* @dholth
* @jezdez
* @kenodegard
* @awwad
* @dependabot[bot]
* @pre-commit-ci[bot]
