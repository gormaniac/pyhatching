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
    private: bool
    submitted: datetime.datetime
    filename: Optional[str] = None
    url: Optional[str] = None


class SamplesResponse(SampleInfo):
    """Response object for POST /samples."""

    completed: datetime.datetime


class YaraRule(BaseModel):
    """A yara rule."""

    name: str
    warnings: Optional[list[str]] = None
    rule: Optional[str] = None


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

    timeout: Optional[int] = None
    network: Optional[enums.SubmssionsRequestNetDefaults] = None


class HatchingProfileSubmission(BaseModel):
    """A sandbox submission profile object."""

    profile: Optional[str] = None
    pick: Optional[str] = None


class SubmissionRequest(HatchingRequest):
    """Request object for POST /samples.

    TODO Document the params here as they aren't anywhere else.
    """

    kind: enums.SubmissionKinds
    url: Optional[str] = None
    target: Optional[str] = None
    interactive: Optional[bool] = None
    password: Optional[str] = None
    profiles: Optional[list[HatchingProfileSubmission]] = None
    user_tags: Optional[list[str]] = None
    defaults: Optional[SubmissionRequestDefaults] = None


class TaskSummary(BaseModel):
    """The summary of a task."""

    sample: str
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


class OverviewAnalysis(BaseModel):
    """Quick overview of analysis results."""

    score: int
    family: Optional[list[str]] = None
    tags: Optional[list[str]] = None


class ReportedFailure(BaseModel):
    """An API failure."""

    reason: str
    task: Optional[str] = None
    backend: Optional[str] = None


class TargetDesc(BaseModel):
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
    filetype: Optional[str] = None
    static_tags: Optional[list[str]] = None


class Indicator(BaseModel):
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


class Signature(BaseModel):
    """A Yara rule hit."""

    label: Optional[str] = None
    name: Optional[str] = None
    score: Optional[int] = None
    ttp: Optional[list[str]] = None
    tags: Optional[list[str]] = None
    indicators: Optional[list[Indicator]] = None
    yara_rule: Optional[str] = None
    desc: Optional[str] = None
    url: Optional[str] = None


class OverviewIOCs(BaseModel):
    """An overview of the IOCs observed during analysis."""

    urls: Optional[list[str]] = None
    domains: Optional[list[str]] = None
    ips: Optional[list[str]] = None


class Credentials(BaseModel):
    """Credentials captured during analysis."""

    user: str
    pass_: str = Field(alias="pass")
    flow: Optional[int] = None
    protocol: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    email_to: Optional[str] = None

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
    shellcode: Optional[list[bytes]] = None
    extracted_pe: Optional[list[str]] = None
    credentials: Optional[list[Credentials]] = None
    attr: Optional[dict] = None
    raw: Optional[str] = None


class Ransom(BaseModel):
    """A ransomware note observed during analysis."""

    note: str
    family: Optional[str] = None
    target: Optional[str] = None
    emails: Optional[list[str]] = None
    wallets: Optional[list[str]] = None
    urls: Optional[list[str]] = None
    contact: Optional[list[str]] = None


class DropperURL(BaseModel):
    """A URL used by a dropper."""

    type: str
    url: str


class Dropper(BaseModel):
    """A malware that downloads other malware."""

    language: str
    urls: list[DropperURL]
    family: Optional[str] = None
    source: Optional[str] = None
    deobfuscated: Optional[str] = None


class OverviewTarget(BaseModel):
    """A summary of the target (analyzed object) and findings."""

    tasks: list[str]
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
    filetype: Optional[str] = None
    static_tags: Optional[list[str]] = None
    tags: Optional[list[str]] = None
    family: Optional[list[str]] = None
    signatures: list[Signature] = None
    iocs: Optional[OverviewIOCs] = None


class OverviewExtracted(BaseModel):
    """Collection of data extracted during analysis."""

    tasks: list[str]
    dumped_file: Optional[str] = None
    resource: Optional[str] = None
    config: Optional[Config] = None
    path: Optional[str] = None
    ransom_note: Optional[Ransom] = None
    dropper: Optional[Dropper] = None
    credentials: Optional[Credentials] = None


class OverviewSample(BaseModel):
    """Information on the analyzed sample, very similar to OverviewTarget but w/o tasks."""

    id: Optional[str] = None
    score: Optional[int] = None
    target: Optional[str] = None
    pick: Optional[str] = None
    type: Optional[str] = None
    size: Optional[int] = None
    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    sha512: Optional[str] = None
    filetype: Optional[str] = None
    static_tags: Optional[list[str]] = None
    submitted: Optional[datetime.datetime] = None
    created: Optional[datetime.datetime] = None
    completed: Optional[datetime.datetime] = None
    iocs: Optional[OverviewIOCs] = None


class OverviewReport(HatchingResponse):
    """The sandbox's overview report for a single sample."""

    version: str
    sample: OverviewSample
    analysis: OverviewAnalysis
    targets: list[OverviewTarget]
    tasks: Optional[list[TaskSummary]] = None
    errors: Optional[list[ReportedFailure]] = None
    signatures: Optional[list[Signature]] = None
    extracted: Optional[list[OverviewExtracted]] = None
