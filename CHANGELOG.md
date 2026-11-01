## Unreleased
### Features
- Support the full Hatching Triage API (public, private, and self-hosted instances).
- Add `pyhatching.testing.FakeTriage`, a fake Triage API server for testing code built on pyhatching.
- Add a live test suite that runs against tria.ge when `HATCHING_TOKEN` is set.
- Publish the Python package to PyPI from the Release GitHub Action.
- Add a manually run Prepare Release GitHub Action that bumps the version, rolls the CHANGELOG, tags, and runs the release.
- Add `make tests` to run the test suite.
### Fixes
- Resolve hashes in the streaming downloads and `kernel_report`.
