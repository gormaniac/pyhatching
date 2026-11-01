# pyhatching

An async HTTP client to interact with the Hatching Triage Sandbox API (tria.ge).

Supports the whole Triage API (public, private, and self-hosted instances):
- Sample submission (files, URLs, fetched URLs, and imports) and interactive profile selection
- Sample searching, listing (owned/org/public), retrieval, and deletion - with pagination
- Sample events (streamed status changes)
- Overview, static, task (triage), summary, UrlScan, and kernel monitor reports
- Sample, task file (pcaps, dropped files, memory dumps, screenshots), and archive downloads
- Analysis profile management (including VPN geolocations)
- Yara rule management
- Resources (analysis environments), geolocations, and usage statistics
- Magic link tokens and organization settings
- User and API key management (private instances)

`pyhatching.testing.FakeTriage` is a fake Triage API server for testing code built on pyhatching.

Read the full documentation [here](https://gormo.co/docs/pyhatching/).

## Releasing

Releases are cut from GitHub Actions with the **Prepare Release** workflow, and pending changes are tracked under a `## Unreleased` header in `CHANGELOG.md`.

1. Add entries to the `## Unreleased` section at the top of `CHANGELOG.md` (under its `### Features` and `### Fixes` headers) as changes land on `main`.
2. Go to **Actions → Prepare Release → Run workflow** on `main`, pick a `patch`/`minor`/`major` bump (or enter an explicit version).

The workflow runs the tests, bumps the version, renames `## Unreleased` to `## v#.#.# - <date>` (starting a fresh empty `## Unreleased` above it), commits, and pushes a `v#.#.#` tag. The **Release** workflow then builds the package, uploads it to PyPI (using the `PYPI_DEPLOY_TOKEN` secret), creates a GitHub Release with the changelog entry as notes and the package and docs attached, and notifies the docs site. Pushing a `v*` tag manually (e.g. `make release VERSION=#.#.#`) also triggers the Release workflow.

`main` is protected, so Prepare Release pushes the release commit and tag with the `RELEASE_TOKEN` repository secret: a token with **Contents: read and write** from an account allowed to bypass the branch protection rule. The tag push starts the Release workflow as its own run under Actions.

The workflows rely on these repository secrets:

- `PYPI_DEPLOY_TOKEN` - the PyPI API token used to upload the package.
- `DOCS_DISPATCH_TOKEN` - used to notify the docs site repo.
- `RELEASE_TOKEN` (required by Prepare Release) - see above. If it expires or is revoked, the push step fails and the token needs to be replaced.
