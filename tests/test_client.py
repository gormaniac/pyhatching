"""Tests for PyHatchingClient against the FakeTriage server."""

import io
import json
import os
import tarfile
import zipfile

import pytest

import pyhatching
from pyhatching import base, enums, errors, utils
from pyhatching import testing as ft


# The fake server listens on localhost, make sure no proxy gets in the way.
os.environ["NO_PROXY"] = ",".join(filter(None, (os.environ.get("NO_PROXY"), "127.0.0.1")))
os.environ["no_proxy"] = os.environ["NO_PROXY"]


@pytest.fixture
async def fake():
    async with ft.FakeTriage() as srv:
        yield srv


@pytest.fixture
async def client(fake):
    async with pyhatching.PyHatchingClient(fake.apikey, url=fake.url) as cli:
        yield cli


@pytest.fixture
async def rclient(fake):
    async with pyhatching.PyHatchingClient(fake.apikey, url=fake.url, raise_on_api_err=True) as cli:
        yield cli


def test_utils():
    assert utils.hash_type(ft.SAMPLE_MD5) == "md5"
    assert utils.hash_type(ft.SAMPLE_SHA1) == "sha1"
    assert utils.hash_type(ft.SAMPLE_SHA256) == "sha256"
    assert utils.hash_type(ft.SAMPLE_SHA512) == "sha512"
    assert utils.hash_type(ft.SAMPLE_SSDEEP) == "ssdeep"
    # Hashes must be the whole value.
    assert utils.hash_type(ft.SAMPLE_MD5 + "zz") is None
    assert not utils.is_hash(ft.SAMPLE_ID)
    assert utils.is_hash(ft.SAMPLE_SHA256)


def test_kernel_log_name():
    assert pyhatching.kernel_log_name({"os": "windows10-2004_x64"}) == "onemon"
    assert pyhatching.kernel_log_name(base.TaskSummary(platform="ubuntu-2204")) == "stahp"
    assert pyhatching.kernel_log_name({"platform": "macos"}) == "bigmac"
    assert pyhatching.kernel_log_name({"os": "android-11"}) == "droidy"
    with pytest.raises(errors.PyHatchingValueError):
        pyhatching.kernel_log_name({"os": "plan9"})


async def test_auth(fake):
    async with pyhatching.PyHatchingClient("badkey", url=fake.url) as cli:
        err = await cli.get_sample(ft.SAMPLE_ID)
        assert isinstance(err, base.ErrorResponse)
        assert err.error == "UNAUTHORIZED" and err.status == 401

    async with pyhatching.PyHatchingClient("badkey", url=fake.url, raise_on_api_err=True) as cli:
        with pytest.raises(errors.PyHatchingApiError) as exc:
            await cli.get_sample(ft.SAMPLE_ID)
        assert exc.value.status == 401 and exc.value.error == "UNAUTHORIZED"

    req = fake.requests[0]
    assert req["headers"]["Authorization"] == "Bearer badkey"
    assert "pyhatching/" in req["headers"]["User-Agent"]


async def test_not_started():
    cli = pyhatching.PyHatchingClient("key")
    with pytest.raises(errors.PyHatchingRequestError):
        await cli.get_profiles()


async def test_conn_error():
    async with pyhatching.PyHatchingClient("key", url="http://127.0.0.1:1", timeout=5) as cli:
        with pytest.raises(errors.PyHatchingRequestError):
            await cli.get_profiles()


async def test_new_client(fake):
    cli = await pyhatching.new_client(fake.apikey, url=fake.url)
    try:
        assert len(await cli.get_profiles()) == 1
    finally:
        await cli.close()


async def test_get_sample(client, fake):
    sample = await client.get_sample(ft.SAMPLE_ID)
    assert isinstance(sample, base.SampleInfo)
    assert sample.status == enums.SubmissionStatuses.REPORTED
    assert sample.filename == "invoice.exe"
    assert [t.id for t in sample.tasks] == ["static1", "behavioral1"]
    assert fake.last()["path"] == f"/api/v0/samples/{ft.SAMPLE_ID}"
    # resp_obj is never dumped.
    assert "resp_obj" not in sample.dict()

    # By hash, uses search to find the ID.
    sample = await client.get_sample(ft.SAMPLE_SHA256)
    assert sample.id == ft.SAMPLE_ID
    search = fake.last(path="/search")
    assert search["query"] == {"query": f"sha256:{ft.SAMPLE_SHA256}", "limit": "1"}

    assert await client.get_sample("a" * 64) is None

    err = await client.get_sample("nope")
    assert isinstance(err, base.ErrorResponse) and err.error == "NOT_FOUND"


async def test_extra_fields(client, fake):
    fake.samples[ft.SAMPLE_ID]["brand_new_field"] = 1
    sample = await client.get_sample(ft.SAMPLE_ID)
    assert sample.dict()["brand_new_field"] == 1


async def test_search_and_list(client, fake):
    for idx in range(5):
        fake.samples[f"261031-x{idx}"] = dict(ft.SAMPLE, id=f"261031-x{idx}")

    hits = await client.search("family:cobaltstrike", limit=3)
    assert len(hits) == 1 and hits[0].id == ft.SAMPLE_ID

    samples = await client.get_samples("public", limit=4)
    assert [s.id for s in samples] == [f"261031-x{i}" for i in (4, 3, 2, 1)]
    assert fake.last()["query"] == {"subset": "public", "limit": "4"}

    samples = await client.get_samples(limit=0)
    assert len(samples) == 6

    page = await client.samples_page(enums.SampleSubsets.ORG, limit=2)
    assert isinstance(page, base.SamplesPage) and len(page.data) == 2 and page.next == "2"
    page2 = await client.samples_page("org", limit=2, offset=page.next)
    assert page2.data[0].id == "261031-x2"
    assert fake.last()["query"]["offset"] == "2"

    ids = [s.id async for s in client.iter_search("", limit=0)]
    assert len(ids) == 6
    ids = [s.id async for s in client.iter_samples("owned", limit=5)]
    assert len(ids) == 5

    err = await client.get_samples("bad")
    assert isinstance(err, base.ErrorResponse) and err.error == "INVALID"
    with pytest.raises(errors.PyHatchingApiError):
        async for _ in client.iter_samples("bad"):
            pass


async def test_pagination_page_sizes(client, fake):
    for idx in range(250):
        fake.samples[f"261031-p{idx:03d}"] = dict(ft.SAMPLE, id=f"261031-p{idx:03d}")
    samples = await client.get_samples(limit=230)
    assert len(samples) == 230
    limits = [r["query"]["limit"] for r in fake.requests if r["path"] == "/api/v0/samples"]
    assert limits == ["200", "30"]


async def test_submit_file(client, fake, tmp_path):
    req = base.SubmissionRequest(
        kind="file",
        interactive=False,
        profiles=[{"profile": "win10-internet", "pick": "invoice.exe"}],
        user_tags=["case:1234"],
        password="infected",
        defaults={"timeout": 120, "network": "sim200"},
    )
    path = tmp_path / "invoice.exe"
    path.write_bytes(b"MZ hello")
    sample = await client.submit_sample(req, path)
    assert isinstance(sample, base.SamplesResponse) and sample.filename == "invoice.exe"

    sent = fake.last("post", "/samples")
    assert sent["files"]["file"] == ("invoice.exe", b"MZ hello")
    body = json.loads(sent["form"]["_json"])
    assert body == {
        "kind": "file",
        "interactive": False,
        "password": "infected",
        "profiles": [{"profile": "win10-internet", "pick": "invoice.exe"}],
        "user_tags": ["case:1234"],
        "defaults": {"timeout": 120, "network": "sim200"},
    }

    # Bytes need a target filename.
    with pytest.raises(errors.PyHatchingValueError):
        await client.submit_sample(base.SubmissionRequest(kind="file"), b"MZ")
    sample = await client.submit_sample(base.SubmissionRequest(kind="file", target="a.dll"), b"MZ")
    assert fake.last("post", "/samples")["files"]["file"] == ("a.dll", b"MZ")

    with pytest.raises(errors.PyHatchingValueError):
        await client.submit_sample(base.SubmissionRequest(kind="file"))
    with pytest.raises(errors.PyHatchingFileError):
        await client.submit_sample(base.SubmissionRequest(kind="file"), tmp_path / "missing")


async def test_submit_url(client, fake):
    req = base.SubmissionRequest(kind="url", url="http://example.com", interactive=True,
                                 user_tags=["phish"])
    sample = await client.submit_sample(req)
    assert sample.kind == enums.SampleKinds.URL and sample.url == "http://example.com"
    assert sample.status == enums.SubmissionStatuses.STATIC_ANALYSIS
    assert fake.last("post", "/samples")["json"] == {
        "kind": "url", "url": "http://example.com", "interactive": True, "user_tags": ["phish"],
    }

    sample = await client.submit_sample(base.SubmissionRequest(kind="fetch", url="http://x.com/a.exe"))
    assert sample.kind == enums.SampleKinds.FETCH and sample.filename == "a.exe"

    with pytest.raises(errors.PyHatchingValueError):
        await client.submit_sample(base.SubmissionRequest(kind="url"))


async def test_set_profile_and_delete(client, rclient, fake):
    sample = await client.submit_sample(
        base.SubmissionRequest(kind="url", url="http://example.com", interactive=True)
    )
    assert await client.set_sample_profile(
        sample.id, [base.HatchingProfileSubmission(profile="win10-internet")]
    ) is None
    assert fake.last()["json"] == {"auto": False, "profiles": [{"profile": "win10-internet"}]}

    err = await client.set_sample_profile(sample.id, auto=True, pick=["a.exe"])
    assert isinstance(err, base.ErrorResponse) and err.error == "PROFILE_NOT_SETTABLE"
    assert fake.last()["json"] == {"auto": True, "pick": ["a.exe"]}
    with pytest.raises(errors.PyHatchingApiError):
        await rclient.set_sample_profile(sample.id, auto=True)

    assert await client.delete_sample(sample.id) is None
    assert fake.last()["method"] == "DELETE"
    assert sample.id not in fake.samples
    err = await client.delete_sample(sample.id)
    assert err.error == "NOT_FOUND"


async def test_events(client, fake):
    events = [e async for e in client.sample_events(ft.SAMPLE_ID)]
    assert [e.status.value for e in events] == ft.EVENTS
    events = [e async for e in client.samples_events()]
    assert len(events) == len(ft.EVENTS)
    with pytest.raises(errors.PyHatchingApiError):
        async for _ in client.sample_events("nope"):
            pass


async def test_reports(client, fake):
    overview = await client.overview(ft.SAMPLE_ID)
    assert isinstance(overview, base.OverviewReport)
    assert fake.last()["path"] == f"/api/v1/samples/{ft.SAMPLE_ID}/overview.json"
    assert overview.analysis.family == ["cobaltstrike"]
    assert overview.sample.sha256 == ft.SAMPLE_SHA256
    config = overview.extracted[0].config
    assert config.c2[0].startswith("http://198.51.100.7")
    creds = config.credentials[0]
    assert creds.username == creds.user == "bot@example.com"
    assert creds.password == creds.pass_ == "hunter2"
    assert creds.dict()["username"] == "bot@example.com"
    assert overview.extracted[1].dropper.urls[0].url == "http://203.0.113.9/a.ps1"
    assert overview.extracted[2].ransom_note.family == "lockbit"
    assert overview.tasks[1].os == "windows10-2004_x64"

    # Old style credentials still validate.
    assert base.Credentials(**{"user": "a", "pass": "b"}).password == "b"

    static = await client.static_report(ft.SAMPLE_SHA256)
    assert isinstance(static, base.StaticReport)
    assert static.files[0].sha256 == ft.SAMPLE_SHA256
    assert fake.last()["path"] == f"/api/v0/samples/{ft.SAMPLE_ID}/reports/static"

    report = await client.task_report(ft.SAMPLE_ID, f"{ft.SAMPLE_ID}-behavioral1")
    assert isinstance(report, base.TriageReport)
    assert fake.last()["path"] == f"/api/v0/samples/{ft.SAMPLE_ID}/behavioral1/report_triage.json"
    assert report.network.flows[0].tls_sni == "evil.example.com"
    assert report.network.ips["198.51.100.7"].asn == "AS64500"
    assert report.processes[1].cmd == ["C:\\Windows\\System32\\cmd.exe", "/c", "whoami"]
    assert report.dumped[0].sha256 == ft.DROPPED_SHA256

    err = await client.task_report(ft.SAMPLE_ID, "behavioral9")
    assert err.error == "REPORT_NOT_AVAILABLE"

    summary = await client.sample_summary(ft.SAMPLE_ID)
    assert summary.score == 10 and f"{ft.SAMPLE_ID}-behavioral1" in summary.tasks

    events = [e async for e in client.kernel_report(ft.SAMPLE_ID, "behavioral1")]
    assert events == ft.KERNEL_EVENTS
    assert fake.last()["path"] == f"/api/v0/samples/{ft.SAMPLE_ID}/behavioral1/logs/onemon.json"
    events = [e async for e in client.kernel_report(ft.SAMPLE_ID, "behavioral1", log="onemon")]
    assert len(events) == 2
    with pytest.raises(errors.PyHatchingValueError):
        async for _ in client.kernel_report(ft.SAMPLE_ID, "behavioral7"):
            pass
    with pytest.raises(errors.PyHatchingApiError):
        async for _ in client.kernel_report(ft.SAMPLE_ID, "behavioral1", log="stahp"):
            pass


async def test_files(client, rclient, fake):
    assert await client.download_sample(ft.SAMPLE_ID) == ft.SAMPLE_BYTES
    assert await client.download_sample(ft.SAMPLE_MD5) == ft.SAMPLE_BYTES
    assert await client.download_sample("nope") is None
    with pytest.raises(errors.PyHatchingApiError) as exc:
        await rclient.download_sample("nope")
    assert exc.value.error == "NOT_FOUND"

    chunks = [c async for c in client.iter_sample(ft.SAMPLE_ID, chunk_size=4)]
    assert b"".join(chunks) == ft.SAMPLE_BYTES

    assert await client.task_pcap(ft.SAMPLE_ID, "behavioral1") == ft.PCAP_BYTES
    assert fake.last()["path"].endswith("/behavioral1/dump.pcap")
    assert await client.task_pcap(ft.SAMPLE_ID, "behavioral1", pcapng=True) == ft.PCAP_BYTES
    byts = await client.task_file(ft.SAMPLE_ID, "behavioral1", "files/0x0003000000022c2b-1.dat")
    assert byts == ft.DROPPED_BYTES
    assert fake.last()["path"] == (
        f"/api/v0/samples/{ft.SAMPLE_ID}/behavioral1/files/0x0003000000022c2b-1.dat"
    )
    chunks = [c async for c in client.iter_task_file(ft.SAMPLE_ID, "behavioral1", "dump.pcap")]
    assert b"".join(chunks) == ft.PCAP_BYTES
    assert await client.task_file(ft.SAMPLE_ID, "behavioral1", "nope.bin") is None

    tar = await client.sample_archive(ft.SAMPLE_ID)
    with tarfile.open(fileobj=io.BytesIO(tar)) as tfd:
        assert f"{ft.SAMPLE_ID}/sample" in tfd.getnames()
    zbyts = b"".join([c async for c in client.iter_sample_archive(ft.SAMPLE_ID, "zip")])
    with zipfile.ZipFile(io.BytesIO(zbyts)) as zfd:
        assert zfd.read(f"{ft.SAMPLE_ID}/sample") == ft.SAMPLE_BYTES
    assert fake.last()["path"].endswith("/archive.zip")
    with pytest.raises(errors.PyHatchingValueError):
        await client.sample_archive(ft.SAMPLE_ID, "rar")


async def test_profiles(client, fake):
    profiles = await client.get_profiles()
    assert [p.name for p in profiles] == ["win10-internet"]
    profile = await client.get_profile("win10-internet")
    assert profile.id == ft.PROFILE["id"]
    assert profile.network == enums.ProfileNetworkOptions.INTERNET

    new = await client.submit_profile("new", ["windows7"], 60, enums.ProfileNetworkOptions.DROP)
    assert new.name == "new" and new.id
    assert fake.last()["json"] == {"name": "new", "tags": ["windows7"], "timeout": 60,
                                   "network": "drop"}
    err = await client.submit_profile("new", [])
    assert err.error == "PROFILE_ALREADY_EXISTS"

    assert await client.update_profile(["windows10"], 90, "tor", "renamed", new.id) is None
    assert fake.last()["method"] == "PUT"
    assert fake.profiles[new.id]["name"] == "renamed"

    assert await client.delete_profile("renamed") is None
    err = await client.delete_profile("renamed")
    assert err.error == "NOT_FOUND"


async def test_yara(client, fake):
    rules = await client.get_rules()
    assert rules.rules[0].name == "fake_rule.yara"
    rule = await client.get_rule("fake_rule.yara")
    assert "pyhatching" in rule.rule

    assert await client.submit_rule("new.yara", "rule a { condition: true }") is None
    assert fake.last()["json"] == {"name": "new.yara", "rule": "rule a { condition: true }"}
    err = await client.submit_rule("bad.yara", "rule a {")
    assert err.error == "COMPILE_ERROR"
    assert await client.update_rule("new.yara", "rule b { condition: false }") is None
    assert fake.rules["new.yara"]["rule"] == "rule b { condition: false }"
    assert await client.delete_rule("new.yara") is None
    assert (await client.delete_rule("new.yara")).error == "NOT_FOUND"


async def test_users(client, fake):
    users = await client.get_users()
    assert users[0].username == "analyst"
    user = await client.get_user(ft.USER["id"])
    assert user.email == "analyst@example.com"

    new = await client.create_user("bob", "bob@example.com", password="pw", permissions=["admin"])
    assert new.username == "bob" and new.id
    assert fake.last()["json"] == {"username": "bob", "email": "bob@example.com",
                                   "password": "pw", "permissions": ["admin"]}

    key = await client.create_user_apikey(new.id, "ci")
    assert key.name == "ci" and key.key
    keys = await client.get_user_apikeys(new.id)
    assert [k.name for k in keys] == ["ci"]
    assert await client.delete_user_apikey(new.id, "ci") is None
    assert await client.get_user_apikeys(new.id) == []

    assert await client.delete_user(new.id) is None
    assert (await client.get_user(new.id)).error == "NOT_FOUND"


async def test_non_json_error(client, fake):
    # Unknown endpoints (aiohttp's own 404 page) still become an ErrorResponse.
    resp, obj = await client._request("get", "/v9/nothing")  # pylint: disable=W0212
    assert resp.status == 404 and obj["error"] == "NOT_FOUND"
