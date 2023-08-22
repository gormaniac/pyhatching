"""Async client to interact with the Hatching Triage Sandbox.

Not a complete client - this library focuses on common use cases.

All client calls return objects (see `pyhatching.base`) instead of dicts,
unless bytes makes more sense for the endpoint (samples, pcaps).

The following examples assume you have imported the following and that the
example code is being executed with an async function::

    import pprint
    import pyhatching

Examples:

- Use a context manager to init the client::

    async with pyhatching.PyHatchingClient(api_key=<token>) as client:
        samples_details = await client.search("tag:beacon")
        pprint.pp([s.dict() for s in samples_details], indent=2)

- Using the ``new_client`` factory method - supports same args as ``PyHatchingClient``::

    client = async pyhatching.new_client(api_key=<token>)
    # Catch all errors handled by Pyhatching
    try:
        sample = client.get_sample(<hash>)
    except pyhatching.errors.PyHatchingError as err:
        print(f"pyhatching didn't work: {err}")
    
    print(sample.dict())
    client.close()  # Don't forget to close the client's session when you're done!

- If you'd like to init the class itself, you'll need to call the ``start()`` method before making any requests::

    client = pyhatching.PyHatchingClient(api_key=<token>)
    await client.start()
    report = await client.overview(<hash>)
    # If the sandbox API returns an error, the return type will reflect that.
    if isinstance(report, pyhatching.base.ErrorResponse):
        print(f"Error: {report}")
    else:
        pprint.pp(report.dict(), indent=2)
    client.close()

- If you don't like the above pattern of ``ErrorResponse`` return types, you can pass ``raise_on_api_err=True`` to ``PyHatchingClient``::

    async with pyhatching.PyHatchingClient(
        api_key=<token>, raise_on_api_err=True
    ) as client:
        try:
            sandbox_profiles = await client.get_profiles()

        # This is the error that get's raised when raise_on_api_err is True
        except pyhatching.errors.PyHatchingApiError as err:
            print(f"The Hatching Triage API returned an err: {err}")

        # Catch the rest of our request errors. Alternatively, we could have
        # caught PyHatchingConnError to replace both this except and the above.
        except pyhatching.errors.PyHatchingRequestError as err:
            print(f"Error connecting to Hatching Triage API: {err}")

        # We'll let other things like validation errors raise for this example
        else:
            pprint.pp(sandbox_profiles)

"""


import functools
import hashlib
from json import JSONDecodeError
import os
import pathlib

import aiohttp
from pydantic.error_wrappers import ValidationError  # pylint: disable=E0611

from . import base
from . import enums
from . import errors
from . import utils


__version__ = "0.2.1"
"""The version of pyhatching."""

BASE_URL = "https://tria.ge"
"""The default URL for requests - the public/free version."""

API_PATH = "/api/v0"
"""The base path used by all API endpoints used for requests."""


def convert_to_model(
    model: base.HatchingResponse,
    resp: aiohttp.ClientResponse,
    obj: dict,
    raise_on_api_err: bool = False,
) -> base.HatchingResponse | list[base.HatchingResponse]:
    """Convert an API response to the given model.

    Parameters
    ----------
    model : base.HatchingResponse
        The model to convert the response to.
    resp : aiohttp.ClientResponse
        The HTTP response object so it can be added to the model.
    obj : dict
        The already deserialized JSON data from the given response.
    raise_on_api_err : bool, optional
        Whether to raise if ``obj`` is actually an API error (``base.ErrorResponse``).
        By default False.

    Returns
    -------
    base.HatchingResponse | list[base.HatchingResponse]
        The API can return either a list or a single item depending on the endpoint
        so can this method. The objects returned are of the same type as ``model``.

    Raises
    ------
    errors.PyHatchingValidateError
        If ``obj`` could not be validated when passed to ``model``. Or when
        ``obj`` is not a dict.
    errors.PyHatchingApiError
        If ``raise_on_api_err`` is ``True`` and ``obj`` represents an error
        returned by the Hatching Triage API and not a successful response.
    """

    ret = []
    url = resp.request_info.url
    try:
        if "data" in obj:
            for item in obj["data"]:
                ret.append(model(resp_obj=obj, **item))
        elif "error" in obj:
            ret = base.ErrorResponse(resp_obj=resp, **obj)
        elif isinstance(obj, dict):
            ret = model(resp_obj=resp, **obj)
        else:
            raise errors.PyHatchingValueError(
                f"Unexpected response from the {url} endpoint: {obj}"
            )
    except ValidationError as err:
        raise errors.PyHatchingValidateError(
            f"Unable to validate {url} response: {err}"
        ) from err

    if raise_on_api_err and isinstance(ret, base.ErrorResponse):
        raise errors.PyHatchingApiError(
            f"Hatching Triage API Error - {ret.error} - {ret.message}"
        )

    return ret


async def new_client(
    api_key: str,
    url: str = BASE_URL,
    timeout: int = 60,
    raise_on_api_err: bool = False,
    **kwargs,
):
    """Factory to create a new ``PyHatchingCLient`` instance."""

    client = PyHatchingClient(
        api_key,
        url,
        timeout,
        raise_on_api_err,
        **kwargs,
    )
    await client.start()
    return client


class PyHatchingClient:
    """An async HTTP client that interfaces with the Hatching Triage Sandbox.

    Any method that makes HTTP requests (calls ``_request``) may raise either
    a ``PyHatchingRequestError`` or ``PyHatchingValidateError``.

    Additionally, any method that returns a Pydantic model (``base.HatchingResponse``)
    may raise a ``PyHatchingValidateError``. If ``raise_on_api_err`` is ``True``, these
    methods may raise a ``PyHatchingApiError`` as well.

    If a specific method also explicitly raises exceptions, it will be documented.

    Catch all handled errors with ``PyHatchingError``.

    Parameters
    ----------
    api_key : str
        The Hatching Triage Sandbox API key to use for requests.
    url : str, optional
        The URL to use as a base in all requests, by default BASE_URL.
    timeout : int, optional
        The total timeout for all requests, by default 60.
    raise_on_api_err : bool, optional
        Whether to raise when the Hatching Triage API returns an API error response
        (an HTTP 200 response that describes a handled error with the request).
        See the `API docs`_ for further information.

    Attributes
    ----------
    api_key : str
        The Hatching Triage Sandbox API key to use for requests.
    headers : dict
        The headers used with every request, has API key and custom User Agent.
    session : aiohttp.ClientSession
        The underlying ClientSession used to make requests.
    timeout : aiohttp.ClientTimeout
        The timeout object used by ``session``.
    convert_resp : typing.Callable
        A ``functools.partial`` for ``convert_to_model`` with ```raise_on_api_err``
        saved so that it doesn't have to be passed to each method call.

    .. _API docs: https://tria.ge/docs/cloud-api/conventions/
    """

    def __init__(
        self,
        api_key: str,
        url: str = BASE_URL,
        timeout: int = 60,
        raise_on_api_err: bool = False,
    ) -> None:
        self.url = url
        self.api_key = api_key
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent": f"{aiohttp.http.SERVER_SOFTWARE} pyhatching/{__version__}",
        }

        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.session = None

        self.convert_resp = functools.partial(
            convert_to_model, raise_on_api_err=raise_on_api_err
        )

    async def __aenter__(
        self,
    ):
        await self.start()
        return self

    async def __aexit__(self, *args):
        await self.close()

    async def start(self):
        """Start the client session."""
        self.session = aiohttp.ClientSession(
            base_url=self.url, headers=self.headers, timeout=self.timeout
        )

    async def close(self):
        """Close the client session."""
        await self.session.close()

    async def _request(
        self,
        method: str,
        uri: str,
        data: aiohttp.MultipartWriter | None = None,
        json: dict | None = None,
        params: dict | None = None,
        raw: bool = False,
    ) -> tuple[aiohttp.ClientResponse, dict]:
        """Make an HTTP request to the Hatching Triage Sandbox API.

        Returns both the response and the deserialized JSON response.

        The response and deserialized JSON are returned regardless of the HTTP
        status code. This way, endpoint specific methods can handle errors. We
        can trust the API to return proper errors, so we'll only raise when there
        are connection issues or unexpected responses.

        Parameters
        ----------
        method : str
            The HTTP method to use for the request.
        uri : str
            The URI (without the session's base_url) to make the request to.
        data : dict | None, optional
            The HTTP form data to send with this request, by default None.
        json : dict | None, optional
            The JSON data to send in this request's HTTP body, by default None.
        params : dict | None, optional
            The URL parameters to send with this request, by default None.
        raw : dict | False, optional
            Return the raw response without calling ``json`` on the response.
            Returns an empty dict as the 2nd return value.

        Returns
        -------
        aiohttp.ClientResponse
            The response object.
        dict
            The response JSON. An error is raised if this couldn't be deserialized.

        Raises
        ------
        PyHatchingRequestError
            If there was an error (not an HTTP response error code)
            in the process of making a request.
        PyHatchingValidateError
            If the JSON response could not be parsed.
        """

        try:
            resp = await self.session.request(
                method, f"{API_PATH}{uri}", data=data, json=json, params=params
            )

            if raw:
                return resp, {}

            resp_json = await resp.json()

        except aiohttp.ClientError as err:
            raise errors.PyHatchingRequestError(
                f"Error making an HTTP request to Hatching Triage: {err}"
            ) from err

        except JSONDecodeError as err:
            raise errors.PyHatchingJsonError(
                f"Unable to parse the response json: {err}"
            ) from err

        return resp, resp_json

    async def norm_sample(self, sample: str) -> str | None:
        """Return a sample ID if sample is a hash, otherwise pass it back."""
        if utils.is_hash(sample):
            sample_id = await self.sample_id(sample)
        else:
            sample_id = sample
        return sample_id

    async def download_sample(self, sample: str) -> bytes | None:
        """Download a sample's bytes by the given ID.

        Parameters
        ----------
        sample : str
            The sample to download, this can be any of the following
            as the value is passed to ``sample_id`` if needed to find the ID::

                sample uuid, md5, sha1, sha2, ssdeep

        Raises
        ------
        PyHatchingError
            When a sample cannot be found.

        Returns
        -------
        bytes
            The downloaded bytes.
        None
            If no bytes can be downloaded or the sample is not found.
        """

        sample_id = await self.norm_sample(sample)
        if sample_id is None:
            return None

        resp, _ = await self._request("get", f"/samples/{sample_id}/sample", raw=True)

        if resp.status == 200:
            sample_bytes = await resp.read()
            return sample_bytes

        return None

    async def get_sample(self, sample: str) -> base.SampleInfo | base.ErrorResponse:
        """Get metadata about a sample by hash or sample ID.

        Parameters
        ----------
        sample : str
            The sample to download, this can be any of the following
            as the value is passed to ``sample_id`` if needed to find the ID::

                sample uuid, md5, sha1, sha2, ssdeep

        Raises
        ------
        PyHatchingError
            When a sample cannot be found.

        Returns
        -------
        base.SampleInfo
            The sample's metadata
        base.ErrorResponse
            If the API returns an error.
        None
            If the sample is not found.
        """

        sample_id = await self.norm_sample(sample)
        if sample_id is None:
            return None

        resp, resp_dict = await self._request("get", f"/samples/{sample}")

        return self.convert_resp(base.SampleInfo, resp, resp_dict)

    async def get_profile(
        self, profile_id: str
    ) -> base.HatchingProfileResponse | base.ErrorResponse:
        """Get a sandbox analysis profile by either ID or name.

        Parameters
        ----------
        profile_id : str
            Either the ``id`` (UUID4) or the name of the profile.

        Returns
        -------
        base.HatchingProfileResponse
            If successful, the requested sandbox profile.
        base.ErrorResponse
            If there was an error.
        """

        resp, resp_dict = await self._request("get", f"/profiles/{profile_id}")

        return self.convert_resp(base.HatchingProfileResponse, resp, resp_dict)

    async def get_profiles(
        self,
    ) -> list[base.HatchingProfileResponse] | base.ErrorResponse:
        """Get all sandbox analysis profiles for your account.

        Returns
        -------
        list[base.HatchingProfileResponse]
            If successful, the requested sandbox profiles.
        base.ErrorResponse
            If there was an error.
        """

        resp, resp_dict = await self._request("get", "/profiles")

        return self.convert_resp(base.HatchingProfileResponse, resp, resp_dict)

    async def get_rule(self, rule_name: str) -> base.YaraRule | base.ErrorResponse:
        """Get a single Yara rule by name.

        Parameters
        ----------
        rule_name : str
            The name of the rule.

        Returns
        -------
        base.YaraRule
            If successful, the returned Yara rule.
        """

        resp, resp_dict = await self._request("get", f"/yara/{rule_name}")

        return self.convert_resp(base.YaraRule, resp, resp_dict)

    async def get_rules(self) -> base.YaraRules | base.ErrorResponse:
        """Get all Yara rules tied to your account.

        Returns
        -------
        base.YaraRules
            If successful, the returned Yara rules.
        """

        resp, resp_dict = await self._request("get", "/yara")

        return self.convert_resp(base.YaraRules, resp, resp_dict)

    async def overview(self, sample: str) -> base.OverviewReport | base.ErrorResponse:
        """Return a sample's Overview Report.

        Parameters
        ----------
        sample : str
            The sample to download, this can be any of the following
            as the value is passed to ``sample_id`` if needed to find the ID::

                sample uuid, md5, sha1, sha2, ssdeep

        Returns
        -------
        base.OverviewReport
            If successful, the return Overview Report.
        base.ErrorResponse
            If there was an error.
        None
            If the sample is not found.
        """

        sample_id = await self.norm_sample(sample)
        if sample_id is None:
            return None

        resp, resp_dict = await self._request(
            "get", f"/samples/{sample_id}/overview.json"
        )

        return self.convert_resp(base.OverviewReport, resp, resp_dict)

    async def sample_id(self, file_hash: str) -> str | None:
        """Find the ID of a sample by the given hash, uses ``search`` under the hood.

        Parameters
        ----------
        file_hash : str
            The hash (md5, sha1, sha2, ssdeep) of the file to get and ID for.

        Returns
        -------
        str
            The sample ID that was found for ``file_hash``.
        None
            The sample ID could not be found.
        """

        hash_prefix = utils.hash_type(file_hash)

        if hash_prefix is None:
            raise errors.PyHatchingValueError(
                f"The input hash is not valid according to 'utils.hash_type': {file_hash}"
            )

        samples = await self.search(f"{hash_prefix}:{file_hash}")

        if isinstance(samples, base.ErrorResponse):
            return None

        if len(samples) > 1:
            # TODO There should only be one sample per hash right?
            return samples[0].id

        return None

    async def search(
        self, query: str
    ) -> list[base.SamplesResponse] | base.ErrorResponse:
        """Search the Hatching Triage Sandbox for samples matching ``query``.

        See the Hatching Triage `docs`_ for how to search.

        Does not handle pagination yet, returns only the first 20 hits!

        Parameters
        ----------
        query : str
            The query string to search for.

        Returns
        -------
        list[base.SamplesResponse]
            A list containing ``SamplesResponse`` objects for each successfully
            returned sample.

        .. _docs: https://tria.ge/docs/cloud-api/search/
        """

        # TODO Handle pagination
        params = {"query": query}

        resp, resp_dict = await self._request("get", "/search", params=params)

        return self.convert_resp(base.SamplesResponse, resp, resp_dict)

    async def submit_profile(
        self,
        name: str,
        tags: list[str],
        timeout: int | None,
        network: enums.ProfileNetworkOptions | None,
    ) -> None | base.ErrorResponse:
        """Add a new sandbox analysis profile to your account.

        Parameters
        ----------
        name : str
            The name of the new profile, must not exist already.
        tags : list[str]
            The tags that match this profile to samples.
            TODO find the documented options
        timeout : int
            The profiles timeout length in seconds.
        network : enums.ProfileNetworkOptions
            The network option for this analysis profile.

        Returns
        -------
        None | base.ErrorResponse
            None if successful, else ``base.ErrorResponse``.
        """

        data = {"name": name, "tags": tags, "timeout": timeout, "network": network}

        resp, resp_dict = await self._request(
            "post", "/profiles", json={k: v for k, v in data.items() if v is not None}
        )

        return self.convert_resp(base.HatchingProfileResponse, resp, resp_dict)

    async def _write_rule(self, method: str, name: str, contents: str):
        """A generic method to create/update a yara rule."""

        data = {"name": name, "rule": contents}

        if method == "put":
            uri = f"/yara/{name}"
        else:
            uri = "/yara"

        resp, resp_dict = await self._request(method, uri, json=data)

        if "error" in resp_dict:
            return self.convert_resp(base.ErrorResponse, resp, resp_dict)

        return None

    async def submit_rule(self, name: str, contents: str) -> base.ErrorResponse | None:
        """Submit a Yara rule to your account.

        Parameters
        ----------
        name : str
            The name of the rule - must not exist already.
        contents : str
            The contents of the Yara rule.

        Returns
        -------
        base.ErrorResponse | None
            None if successful, otherwise the returned ErrorResponse.
        """

        return await self._write_rule("post", name, contents)

    async def _submit_sample(
        self,
        json: dict | None = None,
        data: aiohttp.MultipartWriter | None = None,
    ):
        """Actually make the submit sample HTTP request."""

        resp, resp_dict = await self._request("post", "/samples", json=json, data=data)
        return resp, resp_dict

    async def _submit_fetch(
        self,
        submit_req: base.SubmissionRequest,
    ):
        """Submit a file hosted at a URL for the sandbox to download and analyze."""

        return await self._submit_sample(json=submit_req.dict(exclude_none=True))

    async def _submit_file(
        self,
        submit_req: base.SubmissionRequest,
        sample: bytes | pathlib.Path | str,
    ):
        """Submit a file to the sandbox for analysis."""

        mpwriter = aiohttp.MultipartWriter()

        if isinstance(sample, bytes):
            fpart = mpwriter.append(sample)

            if not submit_req.target:
                fhash = hashlib.md5(sample).hexdigest()
                raise errors.PyHatchingValueError(
                    f"Must specify a filename when passing submitting bytes ({fhash})"
                )

            fpart.set_content_disposition(
                "form-data", name="file", filename=submit_req.target
            )

        else:
            try:
                with open(sample, "rb") as fd:
                    mpwriter.append(fd)
            except OSError as err:
                raise errors.PyHatchingFileError(
                    f"Unable to read {sample}: {err}"
                ) from err

        jpart = mpwriter.append(submit_req.json(exclude_none=True))
        jpart.set_content_disposition("form-data", name="_json")

        return await self._submit_sample(data=mpwriter)

    async def _submit_url(self, url: str):
        """Submit a url to the sandbox for analysis."""

        return await self._submit_sample(json={"url": url})

    async def submit_sample(
        self,
        submit_req: base.SubmissionRequest,
        sample: bytes | pathlib.Path | str | None,
    ) -> base.SamplesResponse | base.ErrorResponse:
        """Submit a sample to the sandbox based on the given ``SubmissionRequest``.

        Parameters
        ----------
        submit_req : base.SubmissionRequest
            The object used to make the request - see this object for details.
        sample : bytes | pathlib.Path | str
            The local file path, url, or raw bytes, to submit to the sandbox.

        Returns
        -------
        base.SamplesResponse
            If successful, the newly created sample object.
        base.ErrorResponse
            If the API reports an error with the submission.
        """

        if submit_req.kind == "file":
            if sample is None:
                raise errors.PyHatchingValueError(
                    "No file specified for file based submission."
                )
            path = os.path.expandvars(os.path.expanduser(sample))
            resp, resp_dict = await self._submit_file(submit_req, path)
        else:
            if submit_req.url is None:
                raise errors.PyHatchingValueError(
                    "No URL specified for url based submission."
                )
            if submit_req.kind == "url":
                resp, resp_dict = await self._submit_url(submit_req.url)
            elif submit_req.kind == "fetch":
                resp, resp_dict = await self._submit_fetch(submit_req)

        return self.convert_resp(base.SamplesResponse, resp, resp_dict)

    async def update_profile(
        self,
        tags: list[str],
        timeout: int,
        network: enums.ProfileNetworkOptions,
        name: str,
        profile_id: str,
    ) -> None | base.ErrorResponse:
        """Update the given profile.

        See `profile docs`_ for how this endpoint behaves, all args are required.

        Does not support name changes - only updating IDs in place.

        Parameters
        ----------
        tags : list[str]
            The tags that match this profile to samples (TODO find documented options).
        timeout : int
            The profiles timeout length in seconds.
        network : enums.ProfileNetworkOptions
            The network option for this analysis profile.
        name : str | None, optional
            The name of the profile. Cannot be set if ``profile_id`` is. By default None.
        profile_id : str | None, optional
            The uuid4 of the profile. Cannot be set if ``name`` is. By default None.

        Returns
        -------
        None | base.ErrorResponse
            None if successful, otherwise a ``base.ErrorResponse``.

        Raises
        ------
        PyHatchingValueError
            If both ``name`` and ``profile_id`` are not set.
            Or if both parameters are set.

        .. _profile docs: https://tria.ge/docs/cloud-api/profiles/
        """

        data = {"name": name, "tags": tags, "timeout": timeout, "network": network}

        resp, resp_dict = await self._request(
            "post", f"/profiles/{profile_id}", json=data
        )

        return self.convert_resp(base.SamplesResponse, resp, resp_dict)

    async def update_rule(self, name: str, contents: str) -> base.ErrorResponse | None:
        """Update an existing Yara rule.

        Parameters
        ----------
        name : str
            The name of the rule - must exist already.
        contents : str
            The new contents of the Yara rule.

        Returns
        -------
        base.ErrorResponse | None
            None if successful, otherwise the returned ErrorResponse.
        """

        return await self._write_rule("put", name, contents)
