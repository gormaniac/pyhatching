"""The pyhatching HTTP client implementation."""

# import asyncio
from json import JSONDecodeError
import pathlib

import aiohttp
# from pydantic.error_wrappers import ValidationError

from . import base
from . import VERSION


BASE_URL = "https://tria.ge/api/v0/"
"""The default URL for requests - the public/free version."""


class PyHatchingError(Exception):
    """An error in the pyhatching client."""


class PyHatchingRequestError(PyHatchingError):
    """An error making a pyhatching HTTP request."""


class PyHatchingParseError(PyHatchingError):
    """An error parsing a pyhatching HTTP response object."""


class PyHatchingClient:
    """An async HTTP client that interfaces with the Hatching Triage Sandbox.

    Parameters
    ----------
    api_key : str
        The Hatching Triage Sandbox to use for requests.
    url : str, optional
        The URL to use as a base in all requests, by default BASE_URL.
    timeout : int, optional
        The total timeout for all requests, by default 60.

    Attributes
    ----------
    api_key : str
    headers : dict
        The headers used with every request, has API key and custom User Agent.
    timeout : aiohttp.ClientTimeout
        The timeout object used by the underlying ClientSession.
    session : aiohttp.ClientSession
        The underlying ClientSession used to make requests.
    """

    def __init__(self, api_key: str, url: str = BASE_URL, timeout: int = 60) -> None:
        self.api_key = api_key
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent": f"pyhatching v{VERSION}",
        }
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.session = aiohttp.ClientSession(
            base_url=url, headers=self.headers, timeout=self.timeout
        )

    async def _request(
        self,
        method: str,
        uri: str,
        data: dict | None = None,
        json: dict | None = None,
        params: dict | None = None,
    ) -> tuple[aiohttp.ClientResponse, dict]:
        """Make an HTTP request to the Hatching Triage Sandbox API.

        Returns both the response and the deserialized JSON response.

        The response and deserialized JSON are returned regardless of the HTTP
        status code. This way, endpoint specific methods can handle errors.

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
            resp_json = await resp.json()
        except aiohttp.ClientError as err:
            raise PyHatchingRequestError(
                f"Error making an HTTP request to Hatching Triage: {err}"
            ) from err
        except JSONDecodeError as err:
            raise PyHatchingParseError(
                f"Unable to parse the response json: {err}"
            ) from err

        return resp, resp_json

    async def download_sample(self, sample: str) -> bytes | None:
        """Download a sample's bytes by the given ID.

        Parameters
        ----------
        sample : str
            The sample to download, this can be any of the following
            as the value is passed to `sample_id` if needed to find the ID::
                sample_id, md5, sha1, sha2, ssdeep

        Returns
        -------
        bytes
            The downloaded bytes.
        None
            If no bytes can be downloaded.
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
            as the value is passed to `sample_id` if needed to find the ID::
                sample_id, md5, sha1, sha2, ssdeep

        Returns
        -------
        base.OverviewReport
            If successful, the return Overview Report.
        """

    async def sample_id(self, file_hash: str) -> str | None:
        """Find the ID of a sample by the given hash, uses `search` under the hood.

        Parameters
        ----------
        file_hash : str
            The hash (md5, sha1, sha2, ssdeep) of the file to get and ID for.

        Returns
        -------
        str
            The sample ID that was found for `file_hash`.
        None
            The sample ID could not be found.
        """

    async def search(self, query: str) -> list[base.SamplesResponse]:
        """Search the Hatching Triage Sandbox for samples matching `query`.

        See the Hatching Triage docs_ for how to search.

        Parameters
        ----------
        query : str
            The query string to search for.

        Returns
        -------
        list[base.SamplesResponse]
            A list containing `SamplesResponse` objects for each successfully
            returned sample.

        _docs: https://tria.ge/docs/cloud-api/search/
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
        """Submit a sample to the sandbox based on the given `SubmissionRequest`.

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
