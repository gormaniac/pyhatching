## Unreleased
### Features
- Add `profiles_page`, `iter_profiles`, `users_page`, and `iter_users`, and a `base.ListPage` model for a single page of a paginated collection (with its `next` offset).
### Fixes
- `get_profiles`, `get_users`, and `get_user_apikeys` now follow the API's pagination and return every item (`limit` caps how many), instead of only the first page with no way to get the next one.
- `FakeTriage` pages like the API: a default page size of 50, at most 200, and API key lists are paginated too.
- Match the live API in `pyhatching.testing`'s task report: DNS record types include their class (`"IN A"`), and `orig` is set on every process in the sample's tree.

## v1.0.0 - 2026-11-01
### Features
- Support the full Hatching Triage API (public, private, and self-hosted instances).
- Add `pyhatching.testing.FakeTriage`, a fake Triage API server for testing code built on pyhatching.
- Add a live test suite that runs against tria.ge when `HATCHING_TOKEN` is set.
- Publish the Python package to PyPI from the Release GitHub Action.
- Add a manually run Prepare Release GitHub Action that bumps the version, rolls the CHANGELOG, tags, and runs the release.
- Add `make tests` to run the test suite.
### Fixes
- Resolve hashes in the streaming downloads and `kernel_report`.

