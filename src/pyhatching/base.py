"""Types for pyhatching."""

import datetime
import json
from typing import Any, Optional

import aiohttp
from pydantic import BaseModel, Field  # pylint: disable=E0611
from pydantic.error_wrappers import (  # pylint: disable=E0611
    ErrorWrapper,
    ValidationError,
)
from pydantic.utils import ROOT_KEY  # pylint: disable=E0611

from . import enums


class HatchingResponse(BaseModel):
    """A response from the Hatching Triage API."""

    resp_obj = aiohttp.ClientResponse


class ErrorResponse(HatchingResponse):
    """An error from the Hatching Triage API."""

    error: enums.ErrorNames
    message: str


class SampleInfo(HatchingResponse):
    """Sample metadata."""

    id: str
    status: enums.SubmissionStatuses
    kind: enums.SampleKinds
    filename: Optional[str]
    url: Optional[str]
    private: bool
    submitted: datetime.datetime


class SamplesResponse(SampleInfo):
    """Response object for POST /samples."""

    completed: datetime.datetime


class YaraRule(BaseModel):
    """A yara rule."""

    name: str
    warnings: Optional[list[str]]
    rule: Optional[str]


class YaraRules(HatchingResponse):
    """A list of yara rules."""

    rules: list[YaraRule]


class HatchingProfile(BaseModel):
    """A Hatching Triage Sandbox analysis profile."""

    name: str
    network: enums.ProfileNetworkOptions
    timeout: int
    tags: list[str] = Field(default_factory=list)


class HatchingProfileResponse(HatchingProfile, HatchingResponse):
    """A HatchingProfile but with `id` and `resp_obj` props."""

    id: str


class HatchingRequest(BaseModel):
    """A request model sent to the Hatching Triage API."""


class SubmissionRequestDefaults(BaseModel):
    """Default sandbox paramaters for SubmissionRequest."""

    timeout: Optional[int]
    network: Optional[enums.SubmssionsRequestNetDefaults]


class HatchingProfileSubmission(BaseModel):
    """A sandbox submission profile object."""

    profile: Optional[str]
    pick: Optional[str]


class SubmissionRequest(HatchingRequest):
    """Request object for POST /samples.

    TODO Document the params here as they aren't anywhere else.
    """

    kind: enums.SubmissionKinds
    url: Optional[str]
    target: Optional[str]
    interactive: Optional[bool]
    password: Optional[str]
    profiles: Optional[list[HatchingProfileSubmission]]
    user_tags: Optional[list[str]]
    defaults: SubmissionRequestDefaults


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
    submitted: Optional[datetime.datetime]
    completed: Optional[datetime.datetime]
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
    at: Optional[int]  # NOTE These had `uint32` go types, does `int` work?
    pid: Optional[int]  # NOTE These had `uint64` go types, does `int` work?
    procid: Optional[int]  # NOTE These had `int32` go types, does `int` work?
    pid_target: Optional[int]  # NOTE These had `uint64` go types, does `int` work?
    procid_target: Optional[int]  # NOTE These had `int32` go types, does `int` work?
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

    pass_: str
    flow: Optional[int]
    protocol: Optional[str]
    host: Optional[str]
    port: Optional[int]
    user: str
    email_to: Optional[str]

    @classmethod
    def parse_obj(cls, obj: Any) -> "Credentials":
        """A custom parsing method to read in "pass" from a dict.
        
        Mostly copies `BaseModel.parse_obj`.
        """

        obj = cls._enforce_dict_if_root(obj)
        if not isinstance(obj, dict):
            try:
                obj = dict(obj)
            except (TypeError, ValueError) as err:
                exc = TypeError(
                    f"{cls.__name__} expected dict not {obj.__class__.__name__}"
                )
                raise ValidationError([ErrorWrapper(exc, loc=ROOT_KEY)], cls) from err

        if "pass" in obj:
            obj["pass_"] = obj.pop("pass")

        return cls(**obj)

    def dict(self, **kwargs: dict) -> dict:
        """Custom dict to get rid of the ``_`` in ``pass_``.

        Attempts to replicate ``BaseModel.dict`` by copying the ``self._iter`` call.
        """

        ret = dict(
            self._iter(
                to_dict=True,
                by_alias=kwargs.get("by_alias", None),
                include=kwargs.get("include", None),
                exclude=kwargs.get("exclude", None),
                exclude_unset=kwargs.get("exclude_unset", None),
                exclude_defaults=kwargs.get("exclude_defaults", None),
                exclude_none=kwargs.get("exclude_none", None),
            )
        )

        if "pass_" in ret:
            ret["pass"] = ret.pop("pass_")

        return ret

    def json(self, **kwargs: dict) -> dict:
        """Custom json that uses this object's custom ``dict`` method."""

        return json.dumps(self.dict(**kwargs))


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
    submitted: Optional[datetime.datetime]
    completed: Optional[datetime.datetime]
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
    submitted: Optional[datetime.datetime]
    created: datetime.datetime
    completed: datetime.datetime
    iocs: Optional[OverviewIOCs]


class OverviewReport(HatchingResponse):
    """The sandbox's overview report for a single sample."""

    version: str
    sample: OverviewSample
    tasks: Optional[list[TaskSummary]]
    analysis: OverviewAnalysis
    targets: list[OverviewTarget]
    errors: Optional[list[ReportedFailure]]
    signatures: Optional[list[Signature]]
    extracted: Optional[list[OverviewExtracted]]
