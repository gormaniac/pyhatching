"""Types for pyhatching.

Every response model allows extra fields, so values the Hatching Triage API adds after
these models were written are kept (and dumped) instead of silently dropped.
"""

import datetime
from typing import Any, Optional

from pydantic import (  # pylint: disable=E0611
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
)

from . import enums


class TriageModel(BaseModel):
    """The base of every pyhatching model, keeps unknown fields from the API."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    def dict(self, **kwargs: Any) -> dict:  # pylint: disable=W0221
        """Dump the model to a dict, using field aliases (the API's names) by default."""

        kwargs.setdefault("by_alias", True)
        return self.model_dump(**kwargs)

    def json(self, **kwargs: Any) -> str:  # pylint: disable=W0221
        """Dump the model to a JSON string, using field aliases by default."""

        kwargs.setdefault("by_alias", True)
        return self.model_dump_json(**kwargs)


class HatchingResponse(TriageModel):
    """A response from the Hatching Triage API.

    ``resp_obj`` is the ``aiohttp.ClientResponse`` the model was built from, it is
    never included when the model is dumped.
    """

    resp_obj: Any = Field(default=None, exclude=True, repr=False)


class ErrorResponse(HatchingResponse):
    """An error from the Hatching Triage API.

    ``error`` is one of ``enums.ErrorNames`` for documented errors, but any string
    the API returns is accepted.
    """

    error: str
    message: str = ""
    status: Optional[int] = None


class SampleTask(TriageModel):
    """A task (a single analysis) of a sample."""

    id: str
    status: Optional[str] = None
    target: Optional[str] = None
    pick: Optional[str] = None


class SampleInfo(HatchingResponse):
    """Sample metadata, returned by GET /samples/{id}, search, and sample listings."""

    id: str
    status: enums.SubmissionStatuses | str = Field(union_mode="left_to_right")
    kind: enums.SampleKinds | str = Field(union_mode="left_to_right")
    private: bool = False
    submitted: Optional[datetime.datetime] = None
    completed: Optional[datetime.datetime] = None
    filename: Optional[str] = None
    url: Optional[str] = None
    tasks: Optional[list[SampleTask]] = None


class SamplesResponse(SampleInfo):
    """Response object for POST /samples (and the items of search results)."""


class ListPage(HatchingResponse):
    """A single page of a paginated collection (ex. GET /profiles, GET /users).

    ``data`` holds the page's items, as the model the endpoint's method documents.
    ``next`` is the offset to request the next page with, ``None`` on the last page.
    """

    data: list[Any] = Field(default_factory=list)
    next: Optional[str] = None


class SamplesPage(HatchingResponse):
    """A single page of samples, from GET /samples or GET /search.

    ``next`` is the offset to request the next page with, ``None`` on the last page.
    """

    data: list[SampleInfo] = Field(default_factory=list)
    next: Optional[str] = None


class YaraRule(HatchingResponse):
    """A yara rule."""

    name: str
    warnings: Optional[list[str]] = None
    rule: Optional[str] = None


class YaraRules(HatchingResponse):
    """A list of yara rules."""

    rules: list[YaraRule] = Field(default_factory=list)


class HatchingProfile(TriageModel):
    """A Hatching Triage Sandbox analysis profile.

    ``geolocation`` picks the VPN region and requires ``network`` to be ``vpn``.
    """

    name: str
    network: enums.ProfileNetworkOptions | str = Field(default="", union_mode="left_to_right")
    timeout: Optional[int] = None
    tags: list[str] = Field(default_factory=list)
    geolocation: Optional[str] = None


class HatchingProfileResponse(HatchingProfile, HatchingResponse):
    """A HatchingProfile but with `id` and `resp_obj` props."""

    id: Optional[str] = None


class User(HatchingResponse):
    """A user of a (private) Hatching Triage instance.

    ``first_name`` and ``last_name`` are deprecated by the API in favor of ``name``.
    """

    id: str
    username: Optional[str] = None
    name: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[str] = None
    email_confirmed_at: Optional[datetime.datetime] = None
    created_at: Optional[datetime.datetime] = None
    company_id: Optional[str] = None
    role: Optional[str] = None
    permissions: Optional[list[str]] = None


class ApiKey(HatchingResponse):
    """An API key of a user."""

    name: Optional[str] = None
    key: Optional[str] = None


class Resource(TriageModel):
    """An analysis environment (VM) for a specific OS, language, and other specifics."""

    name: Optional[str] = None
    tags: list[str] = Field(default_factory=list)


class ResourceGroup(HatchingResponse):
    """A group of analysis environments, from GET /resources."""

    resources: list[Resource] = Field(default_factory=list)


class Geolocation(TriageModel):
    """A region VPN-routed analyses can exit from."""

    name: Optional[str] = None
    tags: list[str] = Field(default_factory=list)


class GeolocationGroup(HatchingResponse):
    """A group of VPN geolocations, from GET /geolocations."""

    geolocations: list[Geolocation] = Field(default_factory=list)


class UsageStats(HatchingResponse):
    """Usage statistics (GET /stats/user and GET /stats/org)."""

    samples_submitted: Optional[int] = None


class MagicLinkSettings(TriageModel):
    """The magic link settings of an organization."""

    enabled: Optional[bool] = None


class OrgSettings(HatchingResponse):
    """Organization settings (GET /org/settings), requires the manage_company permission."""

    magic_link: Optional[MagicLinkSettings] = None


class HatchingRequest(TriageModel):
    """A request model sent to the Hatching Triage API."""


class SubmissionRequestDefaults(TriageModel):
    """Default sandbox paramaters for SubmissionRequest.

    ``geolocation`` picks the VPN region and requires ``network`` to be ``vpn``.
    """

    timeout: Optional[int] = None
    network: enums.SubmssionsRequestNetDefaults | str | None = Field(
        default=None, union_mode="left_to_right"
    )
    geolocation: Optional[str] = None


class HatchingProfileSubmission(TriageModel):
    """A sandbox submission profile object.

    ``profile`` is the name or ID of a profile, ``pick`` the file (in an archive) to run.
    """

    profile: Optional[str] = None
    pick: Optional[str] = None


class SubmissionRequest(HatchingRequest):
    """Request object for POST /samples.

    Parameters
    ----------
    kind
        ``file`` to upload a file, ``url`` to analyze a URL in a browser, ``fetch``
        to have the sandbox download a file from ``url`` and analyze that, or
        ``import`` to import a public Triage sample (its URL or ID in ``url``)
        into a private instance.
    url
        The URL to analyze, fetch, or import - required for the ``url``, ``fetch``,
        and ``import`` kinds.
    target
        The filename to give the sample, defaults to the uploaded file's name.
    interactive
        If true, the sample stops after static analysis until profiles are picked
        with ``PyHatchingClient.set_sample_profile``.
    password
        The password of an encrypted archive.
    profiles
        The profiles to run the sample (or files in it) with. The sandbox picks
        profiles automatically when this is empty.
    user_tags
        Your own tags (strings) for the sample.
    defaults
        The default ``timeout`` (seconds) and ``network`` for automatic profiles.
    """

    kind: enums.SubmissionKinds
    url: Optional[str] = None
    target: Optional[str] = None
    interactive: Optional[bool] = None
    password: Optional[str] = None
    profiles: Optional[list[HatchingProfileSubmission]] = None
    user_tags: Optional[list[str]] = None
    defaults: Optional[SubmissionRequestDefaults] = None


class TaskSummary(TriageModel):
    """The summary of a task."""

    sample: Optional[str] = None
    kind: Optional[str] = None
    name: Optional[str] = None
    status: Optional[str] = None
    ttp: Optional[list[str]] = None
    tags: Optional[list[str]] = None
    score: Optional[int] = None
    target: Optional[str] = None
    backend: Optional[str] = None
    resource: Optional[str] = None
    platform: Optional[str] = None
    task_name: Optional[str] = None
    failure: Optional[str] = None
    queue_id: Optional[int] = None
    pick: Optional[str] = None
    os: Optional[str] = None
    timeout: Optional[int] = None
    sigs: Optional[int] = None


class OverviewAnalysis(TriageModel):
    """Quick overview of analysis results."""

    score: Optional[int] = None
    family: Optional[list[str]] = None
    tags: Optional[list[str]] = None


class ReportedFailure(TriageModel):
    """An analysis failure."""

    reason: str
    task: Optional[str] = None
    backend: Optional[str] = None


class TargetDesc(TriageModel):
    """The description of a target (or analyzed object)."""

    id: Optional[str] = None
    score: Optional[int] = None
    submitted: Optional[datetime.datetime] = None
    completed: Optional[datetime.datetime] = None
    target: Optional[str] = None
    pick: Optional[str] = None
    type: Optional[str] = None
    size: Optional[int] = None
    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    sha512: Optional[str] = None
    ssdeep: Optional[str] = None
    filetype: Optional[str] = None
    static_tags: Optional[list[str]] = None
    user_tags: Optional[list[str]] = None


class Indicator(TriageModel):
    """A single IOC hit of an analyzed sample."""

    ioc: Optional[str] = None
    description: Optional[str] = None
    at: Optional[int] = None
    pid: Optional[int] = None
    procid: Optional[int] = None
    pid_target: Optional[int] = None
    procid_target: Optional[int] = None
    flow: Optional[int] = None
    stream: Optional[int] = None
    dump_file: Optional[str] = None
    resource: Optional[str] = None
    yara_rule: Optional[str] = None


class Signature(TriageModel):
    """A behavioral or Yara signature hit."""

    label: Optional[str] = None
    name: Optional[str] = None
    score: Optional[int] = None
    ttp: Optional[list[str]] = None
    tags: Optional[list[str]] = None
    indicators: Optional[list[Indicator]] = None
    yara_rule: Optional[str] = None
    desc: Optional[str] = None
    url: Optional[str] = None


class OverviewIOCs(TriageModel):
    """An overview of the IOCs observed during analysis."""

    urls: Optional[list[str]] = None
    domains: Optional[list[str]] = None
    ips: Optional[list[str]] = None


class Credentials(TriageModel):
    """Credentials captured during analysis.

    The API names these ``username`` and ``password``. ``user`` and ``pass`` are
    still accepted (and available as properties) for older pyhatching code.
    """

    username: Optional[str] = Field(
        default=None, validation_alias=AliasChoices("username", "user")
    )
    password: Optional[str] = Field(
        default=None, validation_alias=AliasChoices("password", "pass")
    )
    flow: Optional[int] = None
    protocol: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    email_to: Optional[str] = None

    @property
    def user(self) -> Optional[str]:
        """The captured username (an alias of ``username``)."""
        return self.username

    @property
    def pass_(self) -> Optional[str]:
        """The captured password (an alias of ``password``)."""
        return self.password


class Key(TriageModel):
    """A key observed during analysis."""

    kind: Optional[str] = None
    key: Optional[str] = None
    value: Any = None


class Config(TriageModel):
    """A malware samples's configuration extracted during analysis.

    ``shellcode`` items are base64 strings, as the API returns them.
    """

    family: Optional[str] = None
    tags: Optional[list[str]] = None
    rule: Optional[str] = None
    c2: Optional[list[str]] = None
    version: Optional[str] = None
    botnet: Optional[str] = None
    campaign: Optional[str] = None
    mutex: Optional[list[str]] = None
    decoy: Optional[list[str]] = None
    wallet: Optional[list[str]] = None
    dns: Optional[list[str]] = None
    keys: Optional[list[Key]] = None
    webinject: Optional[list[str]] = None
    command_lines: Optional[list[str]] = None
    listen_addr: Optional[str] = None
    listen_port: Optional[int] = None
    listen_for: Optional[list[str]] = None
    shellcode: Optional[list[str]] = None
    extracted_pe: Optional[list[str]] = None
    credentials: Optional[list[Credentials]] = None
    attr: Optional[Any] = None
    raw: Optional[str] = None


class Ransom(TriageModel):
    """A ransomware note observed during analysis."""

    note: Optional[str] = None
    family: Optional[str] = None
    target: Optional[str] = None
    emails: Optional[list[str]] = None
    wallets: Optional[list[str]] = None
    urls: Optional[list[str]] = None
    contact: Optional[list[str]] = None


class DropperURL(TriageModel):
    """A URL used by a dropper."""

    type: Optional[str] = None
    url: str


class Dropper(TriageModel):
    """A malware that downloads other malware."""

    language: Optional[str] = None
    urls: list[DropperURL] = Field(default_factory=list)
    family: Optional[str] = None
    source: Optional[str] = None
    deobfuscated: Optional[str] = None


class Extract(TriageModel):
    """Data extracted from a sample (configs, ransom notes, droppers, credentials)."""

    dumped_file: Optional[str] = None
    resource: Optional[str] = None
    config: Optional[Config] = None
    path: Optional[str] = None
    ransom_note: Optional[Ransom] = None
    dropper: Optional[Dropper] = None
    credentials: Optional[Credentials] = None


class OverviewTarget(TargetDesc):
    """A summary of the target (analyzed object) and findings."""

    tasks: list[str] = Field(default_factory=list)
    tags: Optional[list[str]] = None
    family: Optional[list[str]] = None
    signatures: Optional[list[Signature]] = None
    iocs: Optional[OverviewIOCs] = None


class OverviewExtracted(Extract):
    """Collection of data extracted during analysis, and the tasks it came from."""

    tasks: list[str] = Field(default_factory=list)


class OverviewSample(TargetDesc):
    """Information on the analyzed sample, very similar to OverviewTarget but w/o tasks."""

    created: Optional[datetime.datetime] = None
    iocs: Optional[OverviewIOCs] = None


class OverviewReport(HatchingResponse):
    """The sandbox's overview report for a single sample."""

    version: Optional[str] = None
    sample: OverviewSample = Field(default_factory=OverviewSample)
    analysis: OverviewAnalysis = Field(default_factory=OverviewAnalysis)
    targets: list[OverviewTarget] = Field(default_factory=list)
    tasks: Optional[list[TaskSummary]] = None
    errors: Optional[list[ReportedFailure]] = None
    signatures: Optional[list[Signature]] = None
    extracted: Optional[list[OverviewExtracted]] = None


class ReportSample(TriageModel):
    """The sample section of a static report."""

    sample: Optional[str] = None
    kind: Optional[str] = None
    size: Optional[int] = None
    target: Optional[str] = None
    submitted: Optional[datetime.datetime] = None


class ReportTask(TriageModel):
    """The task section of a static report."""

    task: Optional[str] = None
    target: Optional[str] = None


class ReportAnalysis(TriageModel):
    """The analysis section of a static report."""

    reported: Optional[datetime.datetime] = None
    score: Optional[int] = None
    tags: Optional[list[str]] = None


class FileReport(TriageModel):
    """A file found by static analysis (the sample itself, or a file in it)."""

    filename: Optional[str] = None
    relpath: Optional[str] = None
    filesize: Optional[int] = None
    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    sha512: Optional[str] = None
    ssdeep: Optional[str] = None
    exts: Optional[list[str]] = None
    tags: Optional[list[str]] = None
    filetype: Optional[str] = None
    mime: Optional[str] = None
    depth: Optional[int] = None
    error: Optional[str] = None
    kind: Optional[str] = None
    selected: Optional[bool] = None
    runas: Optional[str] = None
    password: Optional[str] = None


class StaticReport(HatchingResponse):
    """A sample's static analysis report (GET /samples/{id}/reports/static)."""

    version: Optional[str] = None
    sample: ReportSample = Field(default_factory=ReportSample)
    task: ReportTask = Field(default_factory=ReportTask)
    analysis: ReportAnalysis = Field(default_factory=ReportAnalysis)
    signatures: Optional[list[Signature]] = None
    files: Optional[list[FileReport]] = None
    unpack_count: Optional[int] = None
    error_count: Optional[int] = None
    kind: Optional[str] = None
    errors: Optional[list[ReportedFailure]] = None
    extracted: Optional[list[Extract]] = None


class ReportAnalysisInfo(TriageModel):
    """The analysis section of a task (triage) report."""

    score: Optional[int] = None
    tags: Optional[list[str]] = None
    ttp: Optional[list[str]] = None
    features: Optional[list[str]] = None
    submitted: Optional[datetime.datetime] = None
    reported: Optional[datetime.datetime] = None
    max_time_network: Optional[int] = None
    max_time_kernel: Optional[int] = None
    backend: Optional[str] = None
    resource: Optional[str] = None
    resource_tags: Optional[list[str]] = None
    platform: Optional[str] = None


class Process(TriageModel):
    """A process observed during dynamic analysis."""

    procid: Optional[int] = None
    procid_parent: Optional[int] = None
    pid: Optional[int] = None
    ppid: Optional[int] = None
    cmd: Any = None
    image: Optional[str] = None
    # Whether the process is in the sample's process tree. It's set on the sample's children
    # too, and sometimes on none of the processes, so it doesn't find the process that ran it.
    orig: Optional[bool] = None
    started: Optional[int] = None
    terminated: Optional[int] = None


class NetworkFlow(TriageModel):
    """A network flow observed during dynamic analysis."""

    id: Optional[int] = None
    src: Optional[str] = None
    dst: Optional[str] = None
    proto: Optional[str] = None
    pid: Optional[int] = None
    procid: Optional[int] = None
    first_seen: Optional[int] = None
    last_seen: Optional[int] = None
    rx_bytes: Optional[int] = None
    rx_packets: Optional[int] = None
    tx_bytes: Optional[int] = None
    tx_packets: Optional[int] = None
    protocols: Optional[list[str]] = None
    domain: Optional[str] = None
    tls_ja3: Optional[str] = None
    tls_ja3s: Optional[str] = None
    tls_sni: Optional[str] = None


class DNSEntry(TriageModel):
    """A DNS question or answer."""

    name: Optional[str] = None
    # The record class and type, ex. "IN A" or "IN CNAME".
    type: Optional[str] = None
    value: Optional[str] = None


class NetworkDomainRequest(TriageModel):
    """A DNS request."""

    domains: Optional[list[str]] = None
    questions: Optional[list[DNSEntry]] = None


class NetworkDomainResponse(TriageModel):
    """A DNS response."""

    domains: Optional[list[str]] = None
    ip: Optional[list[str]] = None
    answers: Optional[list[DNSEntry]] = None


class NetworkWebRequest(TriageModel):
    """An HTTP request."""

    method: Optional[str] = None
    url: Optional[str] = None
    request: Optional[str] = None
    headers: Optional[list[str]] = None


class NetworkWebResponse(TriageModel):
    """An HTTP response."""

    status: Optional[str] = None
    response: Optional[str] = None
    headers: Optional[list[str]] = None


class NetworkRequest(TriageModel):
    """A DNS or HTTP request (and its response) observed during dynamic analysis."""

    flow: Optional[int] = None
    index: Optional[int] = None
    at: Optional[int] = None
    dns_request: Optional[NetworkDomainRequest] = None
    dns_response: Optional[NetworkDomainResponse] = None
    http_request: Optional[NetworkWebRequest] = None
    http_response: Optional[NetworkWebResponse] = None


class NetworkIP(TriageModel):
    """Information about an IP contacted during dynamic analysis."""

    cidr: Optional[str] = None
    cc: Optional[str] = None
    asn: Optional[str] = None


class NetworkReport(TriageModel):
    """The network section of a task report."""

    flows: Optional[list[NetworkFlow]] = None
    requests: Optional[list[NetworkRequest]] = None
    ips: Optional[dict[str, NetworkIP]] = None


class Dump(TriageModel):
    """A file or memory region dumped during dynamic analysis.

    ``name`` can be downloaded with ``PyHatchingClient.task_file``.
    """

    at: Optional[int] = None
    pid: Optional[int] = None
    procid: Optional[int] = None
    path: Optional[str] = None
    name: Optional[str] = None
    kind: Optional[str] = None
    origin: Optional[str] = None
    addr: Optional[int] = None
    length: Optional[int] = None
    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    sha512: Optional[str] = None
    ssdeep: Optional[str] = None
    size: Optional[int] = None
    nsrl: Optional[str] = None


class TriageReport(HatchingResponse):
    """A task's dynamic analysis report (GET /samples/{id}/{task}/report_triage.json)."""

    version: Optional[str] = None
    sample: TargetDesc = Field(default_factory=TargetDesc)
    task: TargetDesc = Field(default_factory=TargetDesc)
    errors: Optional[list[ReportedFailure]] = None
    analysis: ReportAnalysisInfo = Field(default_factory=ReportAnalysisInfo)
    processes: Optional[list[Process]] = None
    signatures: Optional[list[Signature]] = None
    network: NetworkReport = Field(default_factory=NetworkReport)
    debug: Optional[dict] = None
    dumped: Optional[list[Dump]] = None
    extracted: Optional[list[Extract]] = None


class SampleSummary(HatchingResponse):
    """A short summary of a sample and its tasks (GET /samples/{id}/summary).

    ``tasks`` is keyed by the full task ID (``<sample>-<task>``).
    """

    sample: Optional[str] = None
    status: Optional[str] = None
    kind: Optional[str] = None
    owner: Optional[str] = None
    target: Optional[str] = None
    score: Optional[int] = None
    sha256: Optional[str] = None
    created: Optional[datetime.datetime] = None
    completed: Optional[datetime.datetime] = None
    tasks: Optional[dict[str, dict]] = None
