"""Live tests for PyHatchingClient against the public Hatching Triage API (tria.ge).

These tests are skipped unless ``HATCHING_TOKEN`` holds a tria.ge API key::

    HATCHING_TOKEN=<key> pytest tests/test_live.py -v

They are read-only by default: they list and search public samples, pull every
report for a recent reported sample, and download (in memory only) small files.
Set ``HATCHING_LIVE_WRITE=1`` to also exercise the Yara and profile write
endpoints (objects named ``pyhatching-livetest-*`` are created and deleted).
Set ``HATCHING_LIVE_SUBMIT=1`` to also submit a (benign) URL sample - on the
public cloud submissions are public and can't be deleted, so this is opt-in.
"""

import hashlib
import os

import pytest

import pyhatching
from pyhatching import base, enums, errors


TOKEN = os.environ.get("HATCHING_TOKEN", "")
LIVE_WRITE = os.environ.get("HATCHING_LIVE_WRITE") == "1"
LIVE_SUBMIT = os.environ.get("HATCHING_LIVE_SUBMIT") == "1"

MAX_DOWNLOAD = 20 * 1024 * 1024
"""Don't download samples bigger than this in the download tests."""

pytestmark = pytest.mark.skipif(not TOKEN, reason="HATCHING_TOKEN is not set")

_CACHE: dict = {}
"""Discovered public samples, shared between tests to save API requests."""


@pytest.fixture
async def client():
    async with pyhatching.PyHatchingClient(TOKEN) as cli:
        yield cli


async def _reported_sample(client) -> base.SampleInfo:
    """A recent, reported, public sample with a behavioral task (cached)."""

    if "sample" in _CACHE:
        return _CACHE["sample"]

    async for info in client.iter_samples(enums.SampleSubsets.PUBLIC, limit=50):
        if info.status != enums.SubmissionStatuses.REPORTED or info.kind != enums.SampleKinds.FILE:
            continue
        # The /samples listing omits ``tasks``; only GET /samples/{id} includes them.
        if not info.tasks:
            info = await client.get_sample(info.id)
            if not isinstance(info, base.SampleInfo):
                continue
        if not any("behavioral" in task.id for task in info.tasks or []):
            continue
        _CACHE["sample"] = info
        return info

    pytest.skip("No recent reported public sample with a behavioral task was found.")


async def _overview(client) -> base.OverviewReport:
    if "overview" not in _CACHE:
        sample = await _reported_sample(client)
        report = await client.overview(sample.id)
        assert isinstance(report, base.OverviewReport), f"overview failed: {report}"
        _CACHE["overview"] = report
    return _CACHE["overview"]


async def test_bad_key():
    async with pyhatching.PyHatchingClient("pyhatching-invalid-key") as cli:
        err = await cli.get_samples(limit=1)
        assert isinstance(err, base.ErrorResponse)
        assert err.status == 401 and err.error == "UNAUTHORIZED"


async def test_list_public_samples(client):
    samples = await client.get_samples(enums.SampleSubsets.PUBLIC, limit=5)
    assert isinstance(samples, list) and len(samples) == 5
    assert all(isinstance(s, base.SampleInfo) and s.id for s in samples)

    # Pagination: two pages of two, no overlap, opaque offset round-trips.
    page = await client.samples_page(enums.SampleSubsets.PUBLIC, limit=2)
    assert isinstance(page, base.SamplesPage) and len(page.data) == 2 and page.next
    page2 = await client.samples_page(enums.SampleSubsets.PUBLIC, limit=2, offset=page.next)
    assert isinstance(page2, base.SamplesPage) and len(page2.data) == 2
    assert {s.id for s in page.data}.isdisjoint({s.id for s in page2.data})


async def test_list_owned_samples(client):
    samples = await client.get_samples(enums.SampleSubsets.OWNED, limit=5)
    assert isinstance(samples, list)  # May be empty for a fresh account.


async def test_search(client):
    hits = await client.search(f"md5:{'0' * 32}", limit=1)
    assert hits == []  # A hash that can't exist returns no hits, not an error.

    overview = await _overview(client)
    if overview.sample.sha256:
        hits = await client.search(f"sha256:{overview.sample.sha256}", limit=1)
        assert len(hits) == 1 and hits[0].id

    hits = [s async for s in client.iter_search("tag:trojan", limit=5)]
    assert len(hits) <= 5
    assert all(isinstance(s, base.SampleInfo) for s in hits)


async def test_get_sample_and_hash_resolution(client):
    sample = await _reported_sample(client)
    info = await client.get_sample(sample.id)
    assert isinstance(info, base.SampleInfo)
    assert info.id == sample.id and info.status == enums.SubmissionStatuses.REPORTED

    overview = await _overview(client)
    if overview.sample.sha256:
        # Search by hash resolves to a sample with those bytes - not always the
        # same submission, duplicates return the most recent one.
        resolved = await client.get_sample(overview.sample.sha256)
        assert isinstance(resolved, base.SampleInfo)

    err = await client.get_sample("000000-aaaaaaaaaa")
    assert isinstance(err, base.ErrorResponse) and err.error == "NOT_FOUND"
    assert await client.get_sample("f" * 64) is None


async def test_overview_report(client):
    overview = await _overview(client)
    assert overview.sample.sha256 and len(overview.sample.sha256) == 64
    assert overview.analysis.score is not None
    assert overview.tasks, "A reported sample should have task summaries."
    # resp_obj never leaks into dumps.
    assert "resp_obj" not in overview.dict()


async def test_static_report(client):
    sample = await _reported_sample(client)
    report = await client.static_report(sample.id)
    assert isinstance(report, base.StaticReport), f"static report failed: {report}"
    assert report.files, "A file sample's static report should list files."
    assert report.files[0].sha256


async def test_task_report(client):
    overview = await _overview(client)
    sample = await _reported_sample(client)
    behavioral = next(
        (t for t in overview.tasks or [] if (t.kind or "") == "behavioral"), None
    )
    if behavioral is None:
        pytest.skip("The picked sample has no behavioral task summary.")

    report = await client.task_report(sample.id, behavioral.name)
    assert isinstance(report, base.TriageReport), f"task report failed: {report}"
    assert report.analysis.score is not None

    err = await client.task_report(sample.id, "behavioral99")
    assert isinstance(err, base.ErrorResponse)
    assert err.error in ("NOT_FOUND", "NOT_AVAILABLE", "REPORT_NOT_AVAILABLE")


async def test_summary(client):
    sample = await _reported_sample(client)
    summary = await client.sample_summary(sample.id)
    assert isinstance(summary, base.SampleSummary), f"summary failed: {summary}"
    assert summary.sample == sample.id and summary.tasks


async def test_kernel_report(client):
    overview = await _overview(client)
    sample = await _reported_sample(client)
    behavioral = next(
        (t for t in overview.tasks or [] if (t.kind or "") == "behavioral"), None
    )
    if behavioral is None:
        pytest.skip("The picked sample has no behavioral task summary.")

    count = 0
    try:
        async for event in client.kernel_report(sample.id, behavioral.name):
            assert isinstance(event, dict)
            count += 1
            if count >= 5:
                break
    except errors.PyHatchingApiError as err:
        # Older or special analyses may not keep kernel logs.
        assert err.error in ("NOT_FOUND", "NOT_AVAILABLE", "REPORT_NOT_AVAILABLE"), err


async def test_download_sample(client):
    overview = await _overview(client)
    sample = await _reported_sample(client)
    if (overview.sample.size or 0) > MAX_DOWNLOAD:
        pytest.skip("The picked sample is too big to download in a test.")

    byts = await client.download_sample(sample.id)
    assert byts, "A public sample's bytes should be downloadable."
    if overview.sample.sha256:
        assert hashlib.sha256(byts).hexdigest() == overview.sample.sha256
    if overview.sample.size:
        assert len(byts) == overview.sample.size

    chunks = [c async for c in client.iter_sample(sample.id, chunk_size=64 * 1024)]
    assert b"".join(chunks) == byts

    assert await client.download_sample("f" * 64) is None


async def test_profiles_readonly(client):
    profiles = await client.get_profiles()
    assert isinstance(profiles, list)
    for profile in profiles:
        assert isinstance(profile, base.HatchingProfileResponse) and profile.name


async def test_yara_readonly(client):
    rules = await client.get_rules()
    assert isinstance(rules, base.YaraRules)
    for rule in rules.rules:
        assert rule.name


async def test_resources(client):
    groups = await client.get_resources()
    if isinstance(groups, base.ErrorResponse):
        pytest.skip(f"Resources are not available to this account: {groups.error}")
    assert isinstance(groups, list) and groups
    tags = [t for g in groups for r in g.resources for t in r.tags]
    assert any(t.startswith("os:") for t in tags)


async def test_geolocations(client):
    groups = await client.get_geolocations()
    if isinstance(groups, base.ErrorResponse):
        pytest.skip(f"Geolocations are not available to this account: {groups.error}")
    assert isinstance(groups, list)


async def test_stats(client):
    stats = await client.user_stats()
    if isinstance(stats, base.ErrorResponse):
        pytest.skip(f"User stats are not available to this account: {stats.error}")
    assert stats.samples_submitted is None or stats.samples_submitted >= 0

    stats = await client.org_stats()
    if isinstance(stats, base.ErrorResponse):
        pytest.skip(f"Org stats are not available to this account: {stats.error}")
    assert stats.samples_submitted is None or stats.samples_submitted >= 0


async def test_private_endpoints_fail_gracefully(client):
    """Private-instance endpoints return handled errors on the public cloud."""

    ret = await client.get_users(limit=1)
    assert isinstance(ret, (list, base.ErrorResponse))
    ret = await client.get_org_settings()
    assert isinstance(ret, (base.OrgSettings, base.ErrorResponse))


@pytest.mark.skipif(not LIVE_WRITE, reason="HATCHING_LIVE_WRITE is not set to 1")
async def test_yara_writes(client):
    name = "pyhatching-livetest.yara"
    rule = 'rule pyhatching_livetest { strings: $a = "pyhatching livetest" condition: $a }'
    await client.delete_rule(name)  # Clean up older runs, NOT_FOUND is fine.

    assert await client.submit_rule(name, rule) is None
    try:
        got = await client.get_rule(name)
        assert isinstance(got, base.YaraRule) and "pyhatching livetest" in (got.rule or "")

        updated = rule.replace("livetest", "livetest2")
        assert await client.update_rule(name, updated) is None

        err = await client.submit_rule(name, "rule broken {")
        assert isinstance(err, base.ErrorResponse)
    finally:
        assert await client.delete_rule(name) is None
    err = await client.delete_rule(name)
    assert isinstance(err, base.ErrorResponse) and err.error == "NOT_FOUND"


@pytest.mark.skipif(not LIVE_WRITE, reason="HATCHING_LIVE_WRITE is not set to 1")
async def test_profile_writes(client):
    name = "pyhatching-livetest"
    existing = await client.get_profile(name)
    if isinstance(existing, base.HatchingProfileResponse):
        await client.delete_profile(name)  # Clean up older runs.

    new = await client.submit_profile(name, ["windows10"], 60, "drop")
    assert isinstance(new, base.HatchingProfileResponse), f"profile create failed: {new}"
    try:
        got = await client.get_profile(name)
        assert isinstance(got, base.HatchingProfileResponse)
        assert await client.update_profile(["windows10"], 90, "drop", name, name) is None
    finally:
        assert await client.delete_profile(name) is None


@pytest.mark.skipif(not LIVE_SUBMIT, reason="HATCHING_LIVE_SUBMIT is not set to 1")
async def test_submit_url_sample(client):
    """Submit a benign URL - public on tria.ge and NOT deletable, so opt-in."""

    req = base.SubmissionRequest(
        kind="url", url="http://example.com", user_tags=["pyhatching-livetest"]
    )
    sample = await client.submit_sample(req)
    assert isinstance(sample, base.SamplesResponse), f"submission failed: {sample}"
    assert sample.id and sample.kind == enums.SampleKinds.URL

    # The events stream reports the sample's current status on connect.
    async for event in client.sample_events(sample.id):
        assert event.id == sample.id and event.status
        break
