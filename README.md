# pyhatching

An async HTTP client to interact with the Hatching Triage Sandbox API (tria.ge).

Supports the whole Triage API (public, private, and self-hosted instances):
- Sample submission (files, URLs, and fetched URLs) and interactive profile selection
- Sample searching, listing (owned/org/public), retrieval, and deletion - with pagination
- Sample events (streamed status changes)
- Overview, static, task (triage), summary, and kernel monitor reports
- Sample, task file (pcaps, dropped files, memory dumps, screenshots), and archive downloads
- Analysis profile management
- Yara rule management
- User and API key management (private instances)

`pyhatching.testing.FakeTriage` is a fake Triage API server for testing code built on pyhatching.

Read the full documentation [here](https://gormo.co/docs/pyhatching/).
