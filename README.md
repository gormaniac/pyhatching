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
