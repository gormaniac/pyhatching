"""Types for pyhatching."""

from typing import Any, Optional


from pydantic import BaseModel


class TaskSummary(BaseModel):
    """The summary of a task."""

    sample: str
    kind: Optional[str]
    name: Optional[str]
    status: Optional[str]
    ttp: Optional[list[str]]
    tags: Optional[list[str]]
    score: Optional[int]
    target: Optional[str]
    backend: Optional[str]
    resource: Optional[str]
    platform: Optional[str]
    task_name: Optional[str]
    failure: Optional[str]
    queue_id: Optional[int]
    pick: Optional[str]


class OverviewAnalysis(BaseModel):
    """Quick overview of analysis results."""

    score: int
    family: Optional[list[str]]
    tags: Optional[list[str]]


class ReportedFailure(BaseModel):
    """An API failure."""

    task: Optional[str]
    backend: Optional[str]
    reason: str


class TargetDesc(BaseModel):
    """The description of a target (or analyzed object)."""

    id: Optional[str]
    score: Optional[int]
    submitted: Optional[str]
    completed: Optional[str]
    target: Optional[str]
    pick: Optional[str]
    type: Optional[str]
    size: Optional[int]
    md5: Optional[str]
    sha1: Optional[str]
    sha256: Optional[str]
    sha512: Optional[str]
    filetype: Optional[str]
    static_tags: Optional[list[str]]


class Indicator(BaseModel):
    """A single IOC hit of an analyzed sample."""

    ioc: Optional[str]
    description: Optional[str]
    at: Optional[int]  # NOTE These had `uint32` go types, not sure if `int` works.
    pid: Optional[int]  # NOTE These had `uint64` go types, not sure if `int` works.
    procid: Optional[int]  # NOTE These had `int32` go types, not sure if `int` works.
    pid_target: Optional[
        int
    ]  # NOTE These had `uint64` go types, not sure if `int` works.
    procid_target: Optional[
        int
    ]  # NOTE These had `int32` go types, not sure if `int` works.
    flow: Optional[int]
    stream: Optional[int]
    dump_file: Optional[str]
    resource: Optional[str]
    yara_rule: Optional[str]


class Signature(BaseModel):
    """A Yara rule hit."""

    label: Optional[str]
    name: Optional[str]
    score: Optional[int]
    ttp: Optional[list[str]]
    tags: Optional[list[str]]
    indicators: Optional[list[Indicator]]
    yara_rule: Optional[str]
    desc: Optional[str]
    url: Optional[str]


class OverviewIOCs(BaseModel):
    """An overview of the IOCs observed during analysis."""

    urls: Optional[list[str]]
    domains: Optional[list[str]]
    ips: Optional[list[str]]


class Credentials(BaseModel):
    """Credentials captured during analysis."""

    _pass: str
    flow: Optional[int]
    protocol: Optional[str]
    host: Optional[str]
    port: Optional[int]
    user: str
    email_to: Optional[str]

    def dict(self, **kwargs: dict) -> dict:
        """Custom BaseModel.dict to get rid of the _ in _pass."""

        ret: dict = self.__super__().dict(**kwargs)

        if "_pass" in ret:
            ret["pass"] = ret.pop("_pass")

        return ret


class Key(BaseModel):
    """A key observed during analysis."""

    kind: str
    key: str
    value: Any


class Config(BaseModel):
    """A malware samples's configuration extracted during analysis."""

    family: Optional[str]
    tags: Optional[list[str]]
    rule: Optional[str]
    c2: Optional[list[str]]
    version: Optional[str]
    botnet: Optional[str]
    campaign: Optional[str]
    mutex: Optional[list[str]]
    decoy: Optional[list[str]]
    wallet: Optional[list[str]]
    dns: Optional[list[str]]
    keys: Optional[list[Key]]
    webinject: Optional[list[str]]
    command_lines: Optional[list[str]]
    listen_addr: Optional[str]
    listen_port: Optional[int]
    listen_for: Optional[list[str]]
    shellcode: Optional[list[bytes]]
    extracted_pe: Optional[list[str]]
    credentials: Optional[list[Credentials]]
    attr: Optional[dict]
    raw: Optional[str]


class Ransom(BaseModel):
    """A ransomware note observed during analysis."""

    family: Optional[str]
    target: Optional[str]
    emails: Optional[list[str]]
    wallets: Optional[list[str]]
    urls: Optional[list[str]]
    contact: Optional[list[str]]
    note: str


class DropperURL(BaseModel):
    """A URL used by a dropper."""

    type: str
    url: str


class Dropper(BaseModel):
    """A malware that downloads other malware."""

    family: Optional[str]
    language: str
    source: Optional[str]
    deobfuscated: Optional[str]
    urls: list[DropperURL]


class OverviewTarget(BaseModel):
    """A summary of the target (analyzed object) and findings."""

    tasks: list[str]
    id: Optional[str]
    score: Optional[int]
    submitted: Optional[str]
    completed: Optional[str]
    target: Optional[str]
    pick: Optional[str]
    type: Optional[str]
    size: Optional[int]
    md5: Optional[str]
    sha1: Optional[str]
    sha256: Optional[str]
    sha512: Optional[str]
    filetype: Optional[str]
    static_tags: Optional[list[str]]
    tags: Optional[list[str]]
    family: Optional[list[str]]
    signatures: list[Signature]
    iocs: Optional[OverviewIOCs]


class OverviewExtracted(BaseModel):
    """Collection of data extracted during analysis."""

    tasks: list[str]
    dumped_file: Optional[str]
    resource: Optional[str]
    config: Optional[Config]
    path: Optional[str]
    ransom_note: Optional[Ransom]
    dropper: Optional[Dropper]
    credentials: Optional[Credentials]


class OverviewSample(BaseModel):
    """Information on the analyzed sample, very similar to OverviewTarget but w/o tasks."""

    id: Optional[str]
    score: Optional[int]
    submitted: Optional[str]
    completed: Optional[str]
    target: Optional[str]
    pick: Optional[str]
    type: Optional[str]
    size: Optional[int]
    md5: Optional[str]
    sha1: Optional[str]
    sha256: Optional[str]
    sha512: Optional[str]
    filetype: Optional[str]
    static_tags: Optional[list[str]]
    created: str
    completed: str
    iocs: Optional[OverviewIOCs]


class OverviewReport(BaseModel):
    """The sandbox's overview report for a single sample."""

    version: str
    sample: OverviewSample
    tasks: Optional[list[TaskSummary]]
    analysis: OverviewAnalysis
    targets: list[OverviewTarget]
    errors: Optional[list[ReportedFailure]]
    signatures: Optional[list[Signature]]
    extracted: Optional[list[OverviewExtracted]]
