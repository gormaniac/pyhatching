"""The pyhatching HTTP client implementation."""

# import asyncio
import functools
from json import JSONDecodeError
import pathlib

import aiohttp
from pydantic.error_wrappers import ValidationError  # pylint: disable=E0611

from . import base
from . import enums
from . import errors
from . import utils
from . import BASE_URL, __version__


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
    errors.PyHatchingParseError
        If ``obj`` could not be validated when passed to ``model``. Or when
        ``obj`` is not a dict.
    errors.PyHatchingResponseError
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
            raise errors.PyHatchingParseError(
                f"Unexpected response from the {url} endpoint: {obj}"
            )
    except ValidationError as err:
        raise errors.PyHatchingParseError(
            f"Unable to validate {url} response: {err}"
        ) from err

    if raise_on_api_err and isinstance(ret, base.ErrorResponse):
        raise errors.PyHatchingResponseError(
            f"Hatching Triage API Error - {ret.error} - {ret.message}"
        )

    return ret


class PyHatchingClient:
    """An async HTTP client that interfaces with the Hatching Triage Sandbox.

    Any method that makes HTTP requests (calls ``_request``) may raise either
    a ``PyHatchingRequestError`` or ``PyHatchingParseError``.

    Additionally, any method that returns a Pydantic model (``base.HatchingResponse``)
    may raise a ``PyHatchingParseError``. If ``raise_on_api_err`` is ``True``, these
    methods may raise a ``PyHatchingResponseError`` as well.
    
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
        See the `docs`_ for further information.

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

    .. _docs: https://tria.ge/docs/cloud-api/conventions/
    """

    def __init__(
        self,
        api_key: str,
        url: str = BASE_URL,
        timeout: int = 60,
        raise_on_api_err: bool = False,
    ) -> None:
        self.api_key = api_key
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent": f"{aiohttp.http.SERVER_SOFTWARE} pyhatching/{__version__}",
        }
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.session = aiohttp.ClientSession(
            base_url=url, headers=self.headers, timeout=self.timeout
        )

        self.convert_resp = functools.partial(
            convert_to_model, raise_on_api_err=raise_on_api_err
        )

    async def _request(
        self,
        method: str,
        uri: str,
        data: dict | None = None,
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
        PyHatchingParseError
            If the JSON response could not be parsed.
        """

        try:
            resp = await self.session.request(
                method, uri, data=data, json=json, params=params
            )

            if raw:
                return resp, {}

            resp_json = await resp.json()

        except aiohttp.ClientError as err:
            raise errors.PyHatchingRequestError(
                f"Error making an HTTP request to Hatching Triage: {err}"
            ) from err

        except JSONDecodeError as err:
            raise errors.PyHatchingParseError(
                f"Unable to parse the response json: {err}"
            ) from err

        return resp, resp_json

    async def download_sample(self, sample: str) -> bytes | None:
        """Download a sample's bytes by the given ID.

        Parameters
        ----------
        sample : str
            The sample to download, this can be any of the following
            as the value is passed to ``sample_id`` if needed to find the ID::

                sample_id, md5, sha1, sha2, ssdeep

        Returns
        -------
        bytes
            The downloaded bytes.
        None
            If no bytes can be downloaded.
        """

        if utils.is_hash(sample):
            sample_id = await self.sample_id(sample)
        else:
            sample_id = sample

        if sample_id is None:
            raise errors.PyHatchingParseError(
                f"Unable to determine sample_id from: {sample}"
            )

        resp, _ = await self._request("get", f"/samples/{sample_id}/sample", raw=True)

        if resp.status == 200:
            sample_bytes = await resp.read()
            return sample_bytes

        return None

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

    async def get_rule(self, rule_name: str) -> base.YaraRule:
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

    async def get_rules(self) -> base.YaraRules:
        """Get all Yara rules tied to your account.

        Returns
        -------
        base.YaraRules
            If successful, the returned Yara rules.
        """

    async def overview(self, sample: str) -> base.OverviewReport:
        """Return a sample's Overview Report.

        Parameters
        ----------
        sample : str
            The sample to download, this can be any of the following
            as the value is passed to ``sample_id`` if needed to find the ID::

                sample_id, md5, sha1, sha2, ssdeep

        Returns
        -------
        base.OverviewReport
            If successful, the return Overview Report.
        """

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
            raise errors.PyHatchingParseError(
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
        timeout: int,
        network: enums.ProfileNetworkOptions,
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

    async def submit_sample(
        self,
        submit_req: base.SubmissionRequest,
        sample: bytes | pathlib.Path | str,
    ) -> base.SamplesResponse:
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
        """

    async def update_profile(
        self,
        tags: list[str],
        timeout: int,
        network: enums.ProfileNetworkOptions,
        name: str | None = None,
        profile_id: str | None = None,
    ) -> None | base.ErrorResponse:
        """Update the given profile.

        One of ``name`` or ``profile_id`` must be set. Otherwise, ValueError is raised.
        Both parameters cannot be used at the same time.

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
        ValueError
            If both ``name`` and ``profile_id`` are not set.
            Or if both parameters are set.
        """

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
