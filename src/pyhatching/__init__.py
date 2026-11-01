"""Async client to interact with the Hatching Triage Sandbox.

Supports the whole Hatching Triage API: sample submission, listing, searching,
deletion, and events; every report (overview, static, task, summary, UrlScan, and
kernel logs); sample, task file, pcap, screenshot, and archive downloads; analysis
profiles; Yara rules; resources, geolocations, and usage statistics; magic links;
and (private instance) user, API key, and organization management.

All client calls return objects (see `pyhatching.base`) instead of dicts,
unless bytes makes more sense for the endpoint (samples, pcaps). Streaming
endpoints (events, kernel logs, chunked downloads) are async generators.

The following examples assume you have imported the following and that the
example code is being executed with an async function::

    import pprint
    import pyhatching

Examples:

- Use a context manager to init the client::

    async with pyhatching.PyHatchingClient(api_key=<token>) as client:
        samples_details = await client.search("tag:beacon")
        pprint.pp([s.dict() for s in samples_details], indent=2)

- Use a private Triage instance (or any other API root)::

    async with pyhatching.PyHatchingClient(
        api_key=<token>, url=pyhatching.PRIVATE_URL
    ) as client:
        async for sample in client.iter_samples("org", limit=500):
            print(sample.id, sample.status)

- Using the ``new_client`` factory method - supports same args as ``PyHatchingClient``::

    client = await pyhatching.new_client(api_key=<token>)
    # Catch all errors handled by Pyhatching
    try:
        sample = await client.get_sample(<hash>)
    except pyhatching.errors.PyHatchingError as err:
        print(f"pyhatching didn't work: {err}")
    
    print(sample.dict())
    await client.close()  # Don't forget to close the client's session when you're done!

- If you'd like to init the class itself, you'll need to call the ``start()`` method before making any requests::

    client = pyhatching.PyHatchingClient(api_key=<token>)
    await client.start()
    report = await client.overview(<hash>)
    # If the sandbox API returns an error, the return type will reflect that.
    if isinstance(report, pyhatching.base.ErrorResponse):
        print(f"Error: {report}")
    else:
        pprint.pp(report.dict(), indent=2)
    await client.close()

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
import json as jsonlib
import os
import pathlib
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import quote

import aiohttp
from pydantic import ValidationError  # pylint: disable=E0611

from . import base
from . import enums
from . import errors
from . import utils


__version__ = "0.3.1"
"""The version of pyhatching."""

BASE_URL = "https://tria.ge"
"""The default URL for requests - the public/free version."""

PRIVATE_URL = "https://private.tria.ge"
"""The URL of the private Hatching Triage cloud."""

API_PATH = "/api"
"""The path, appended to the URL, that all versioned (``/v0``, ``/v1``) endpoints live under."""

MAX_PAGE_SIZE = 200
"""The most items the API returns in a single page."""

CHUNK_SIZE = 1024 * 1024
"""The default size of the chunks yielded by the ``iter_*`` download methods."""


def _seg(valu: Any) -> str:
    """Quote a value for use as a single URL path segment."""

    return quote(str(valu), safe="")


def _params(params: dict) -> dict:
    """Drop the ``None`` values from a dict of URL params (aiohttp rejects them)."""

    ret = {}
    for key, valu in params.items():
        if valu is None:
            continue
        if isinstance(valu, bool):
            valu = "true" if valu else "false"
        ret[key] = valu if isinstance(valu, str) else str(valu)
    return ret


def _value(valu: Any) -> Any:
    """Return the value of an Enum, or the value itself."""

    return getattr(valu, "value", valu)


def http_error_name(status: int) -> str:
    """The Hatching Triage error name for an HTTP status, used when the API returns no JSON."""

    return {
        400: enums.ErrorNames.BAD_REQUEST.value,
        401: enums.ErrorNames.UNAUTHORIZED.value,
        403: enums.ErrorNames.FORBIDDEN.value,
        404: enums.ErrorNames.NOT_FOUND.value,
        405: enums.ErrorNames.METHOD_NOT_ALLOWED.value,
        429: enums.ErrorNames.TOO_MANY_REQUESTS.value,
    }.get(status, enums.ErrorNames.INTERNAL.value if status >= 500 else f"HTTP_{status}")


def kernel_log_name(task: base.TaskSummary | dict) -> str:
    """The kernel monitor log name (ex. ``onemon``) of a task, based on its OS/platform.

    Raises
    ------
    errors.PyHatchingValueError
        If the task's platform has no known kernel log.
    """

    if isinstance(task, base.TaskSummary):
        task = task.model_dump()
    platform = f"{task.get('os') or ''} {task.get('platform') or ''}".lower()
    if "windows" in platform:
        return enums.KernelLogs.WINDOWS.value
    if "linux" in platform or "ubuntu" in platform:
        return enums.KernelLogs.LINUX.value
    if "macos" in platform:
        return enums.KernelLogs.MACOS.value
    if "android" in platform:
        return enums.KernelLogs.ANDROID.value
    raise errors.PyHatchingValueError(f"No kernel log is known for the platform: {platform.strip()}")


def convert_to_model(
    model: type[base.HatchingResponse],
    resp: aiohttp.ClientResponse,
    obj: dict,
    raise_on_api_err: bool = False,
) -> base.HatchingResponse | list[base.HatchingResponse]:
    """Convert an API response to the given model.

    Parameters
    ----------
    model : type[base.HatchingResponse]
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
        Lists (``{"data": [...]}`` responses) are returned as a list of ``model``,
        unless ``model`` itself has a ``data`` field (ex. ``base.SamplesPage``).
        Errors are returned as a ``base.ErrorResponse``.

    Raises
    ------
    errors.PyHatchingValidateError
        If ``obj`` could not be validated when passed to ``model``. Or when
        ``obj`` is not a dict.
    errors.PyHatchingApiError
        If ``raise_on_api_err`` is ``True`` and ``obj`` represents an error
        returned by the Hatching Triage API and not a successful response.
    """

    url = resp.request_info.url if resp is not None else None
    status = getattr(resp, "status", None)

    if not isinstance(obj, dict):
        raise errors.PyHatchingValidateError(
            f"Unexpected response from the {url} endpoint: {obj}"
        )

    try:
        if "error" in obj and (status is None or status >= 400 or "message" in obj):
            ret = base.ErrorResponse(resp_obj=resp, status=status, **obj)
        elif "data" in obj and "data" not in model.model_fields:
            ret = [model(resp_obj=resp, **item) for item in obj["data"] or []]
        else:
            ret = model(resp_obj=resp, **obj)
    except (ValidationError, TypeError) as err:
        raise errors.PyHatchingValidateError(
            f"Unable to validate {url} response: {err}"
        ) from err

    if raise_on_api_err and isinstance(ret, base.ErrorResponse):
        raise api_error(ret)

    return ret


def api_error(err: base.ErrorResponse) -> errors.PyHatchingApiError:
    """Create a ``PyHatchingApiError`` from an ``ErrorResponse``."""

    return errors.PyHatchingApiError(
        f"Hatching Triage API Error - {err.error} - {err.message}",
        status=err.status,
        error=err.error,
        message=err.message,
    )


async def new_client(
    api_key: str,
    url: str = BASE_URL,
    timeout: int = 60,
    raise_on_api_err: bool = False,
    **kwargs,
):
    """Factory to create a new ``PyHatchingClient`` instance and start its session."""

    client = PyHatchingClient(
        api_key,
        url,
        timeout,
        raise_on_api_err,
        **kwargs,
    )
    await client.start()
    return client


class PyHatchingClient:  # pylint: disable=R0904
    """An async HTTP client that interfaces with the Hatching Triage Sandbox.

    Any method that makes HTTP requests (calls ``_request``) may raise either
    a ``PyHatchingRequestError`` or ``PyHatchingValidateError``.

    Additionally, any method that returns a Pydantic model (``base.HatchingResponse``)
    may raise a ``PyHatchingValidateError``. If ``raise_on_api_err`` is ``True``, these
    methods may raise a ``PyHatchingApiError`` as well.

    Async generators (the ``iter_*``, ``*_events``, and ``kernel_report`` methods)
    can't return an ``ErrorResponse``, so they always raise ``PyHatchingApiError``.

    If a specific method also explicitly raises exceptions, it will be documented.

    Catch all handled errors with ``PyHatchingError``.

    Parameters
    ----------
    api_key : str
        The Hatching Triage Sandbox API key to use for requests.
    url : str, optional
        The URL to use as a base in all requests, by default BASE_URL.
        Use ``PRIVATE_URL`` for the private cloud.
    timeout : int, optional
        The total timeout for all requests, by default 60. Streaming requests
        (events, chunked downloads) only use it to connect.
    raise_on_api_err : bool, optional
        Whether to raise when the Hatching Triage API returns an API error response.
        See the `API docs`_ for further information.
    api_path : str, optional
        The path the versioned endpoints live under, by default ``API_PATH``.
        Use an empty string for an API root like ``https://api.tria.ge``.
    trust_env : bool, optional
        Whether the HTTP session uses proxy settings from the environment, by default True.

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

    def __init__(  # pylint: disable=R0913
        self,
        api_key: str,
        url: str = BASE_URL,
        timeout: int = 60,
        raise_on_api_err: bool = False,
        api_path: str = API_PATH,
        trust_env: bool = True,
    ) -> None:
        self.url = url.rstrip("/")
        self.api_path = api_path.rstrip("/")
        self.api_key = api_key
        self.raise_on_api_err = raise_on_api_err
        self.trust_env = trust_env
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent": f"{aiohttp.http.SERVER_SOFTWARE} pyhatching/{__version__}",
        }

        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.stream_timeout = aiohttp.ClientTimeout(
            total=None, connect=timeout, sock_connect=timeout
        )
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
            headers=self.headers, timeout=self.timeout, trust_env=self.trust_env
        )

    async def close(self):
        """Close the client session."""
        if self.session is not None:
            await self.session.close()

    def _url(self, uri: str) -> str:
        """The full URL of an API path (ex. ``/v0/samples``)."""

        return f"{self.url}{self.api_path}{uri}"

    @staticmethod
    def _load(resp: aiohttp.ClientResponse, text: str) -> dict:
        """Deserialize a response body, turning non-JSON error bodies into an API error."""

        if not text.strip():
            if resp.status >= 400:
                return {"error": http_error_name(resp.status), "message": resp.reason or ""}
            return {}
        try:
            return jsonlib.loads(text)
        except ValueError as err:
            if resp.status >= 400:
                return {"error": http_error_name(resp.status), "message": text[:500]}
            raise errors.PyHatchingJsonError(
                f"Unable to parse the response json: {err}"
            ) from err

    async def _request(  # pylint: disable=R0913
        self,
        method: str,
        uri: str,
        data: Any = None,
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
            The URI (without the URL and API path, ex. ``/v0/samples``) to request.
        data : Any, optional
            The HTTP form data to send with this request, by default None.
        json : dict | None, optional
            The JSON data to send in this request's HTTP body, by default None.
        params : dict | None, optional
            The URL parameters to send with this request, by default None.
        raw : bool, optional
            Return the response without reading its body. Returns an empty dict
            as the 2nd return value. The caller must release the response.

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
        PyHatchingJsonError
            If the JSON response could not be parsed.
        """

        if self.session is None:
            raise errors.PyHatchingRequestError(
                "The client session isn't started, use start() or a context manager."
            )

        kwargs = {}
        if raw:
            kwargs["timeout"] = self.stream_timeout

        try:
            resp = await self.session.request(
                method,
                self._url(uri),
                data=data,
                json=json,
                params=_params(params or {}),
                **kwargs,
            )

            if raw:
                return resp, {}

            text = await resp.text()

        except (aiohttp.ClientError, TimeoutError) as err:
            raise errors.PyHatchingRequestError(
                f"Error making an HTTP request to Hatching Triage: {err}"
            ) from err

        return resp, self._load(resp, text)

    async def _model(self, model, method: str, uri: str, **kwargs):
        """Make a request and convert its response to ``model``."""

        resp, resp_dict = await self._request(method, uri, **kwargs)
        return self.convert_resp(model, resp, resp_dict)

    async def _empty(self, method: str, uri: str, **kwargs) -> None | base.ErrorResponse:
        """Make a request whose successful response has no content, returning None or the error."""

        resp, resp_dict = await self._request(method, uri, **kwargs)
        if resp.status < 400 and not (isinstance(resp_dict, dict) and "error" in resp_dict):
            return None
        return self.convert_resp(base.ErrorResponse, resp, resp_dict)

    async def _raw_error(self, resp: aiohttp.ClientResponse) -> base.ErrorResponse:
        """Read an error response returned for a raw request (and release it)."""

        try:
            text = await resp.text()
        except aiohttp.ClientError:
            text = ""
        finally:
            resp.release()
        obj = self._load(resp, text)
        if not isinstance(obj, dict) or "error" not in obj:
            obj = {"error": http_error_name(resp.status), "message": text[:500]}
        return base.ErrorResponse(resp_obj=resp, status=resp.status, **obj)

    async def _iter_bytes(self, uri: str, chunk_size: int = CHUNK_SIZE) -> AsyncIterator[bytes]:
        """Download a file in chunks, raising a ``PyHatchingApiError`` if it isn't available."""

        resp, _ = await self._request("get", uri, raw=True)
        if resp.status >= 300:
            raise api_error(await self._raw_error(resp))
        try:
            async for chunk in resp.content.iter_chunked(chunk_size):
                yield chunk
        except (aiohttp.ClientError, TimeoutError) as err:
            raise errors.PyHatchingRequestError(
                f"Error downloading {uri} from Hatching Triage: {err}"
            ) from err
        finally:
            resp.release()

    async def _bytes(self, uri: str) -> bytes | None:
        """Download a file, returning None (or raising, with raise_on_api_err) if it's unavailable."""

        try:
            return b"".join([chunk async for chunk in self._iter_bytes(uri)])
        except errors.PyHatchingApiError:
            if self.raise_on_api_err:
                raise
            return None

    async def _iter_json_lines(self, uri: str) -> AsyncIterator[dict]:
        """Stream a newline delimited JSON response, yielding each object."""

        resp, _ = await self._request("get", uri, raw=True)
        if resp.status >= 300:
            raise api_error(await self._raw_error(resp))
        buf = b""
        try:
            async for chunk in resp.content.iter_any():
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if line.strip():
                        yield self._json_line(line)
            if buf.strip():
                yield self._json_line(buf)
        except (aiohttp.ClientError, TimeoutError) as err:
            raise errors.PyHatchingRequestError(
                f"Error streaming {uri} from Hatching Triage: {err}"
            ) from err
        finally:
            resp.release()

    @staticmethod
    def _json_line(line: bytes) -> dict:
        try:
            return jsonlib.loads(line)
        except ValueError as err:
            raise errors.PyHatchingJsonError(f"Unable to parse a streamed JSON line: {err}") from err

    @staticmethod
    def _task(sample_id: str, task: str) -> str:
        """Strip the sample ID from a full task ID (ex. ``<sample>-behavioral1``)."""

        prefix = f"{sample_id}-"
        if task.startswith(prefix):
            return task[len(prefix):]
        return task

    # ---- Samples ----

    async def norm_sample(self, sample: str) -> str | None:
        """Return a sample ID if sample is a hash, otherwise pass it back."""
        if utils.is_hash(sample):
            sample_id = await self.sample_id(sample)
        else:
            sample_id = sample
        return sample_id

    async def _stream_sample(self, sample: str) -> str:
        """``norm_sample`` for generators, which raise when a hash has no sample."""

        sample_id = await self.norm_sample(sample)
        if sample_id is None:
            raise errors.PyHatchingApiError(
                f"Hatching Triage has no sample for {sample}",
                status=404,
                error=enums.ErrorNames.NOT_FOUND.value,
                message=f"No sample for {sample}",
            )
        return sample_id

    async def sample_id(self, file_hash: str) -> str | None:
        """Find the ID of a sample by the given hash, uses ``search`` under the hood.

        The most recent sample is returned when the file was submitted more than once.

        Parameters
        ----------
        file_hash : str
            The hash (md5, sha1, sha256, sha512, ssdeep) of the file to get and ID for.

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

        page = await self.search_page(f"{hash_prefix}:{file_hash}", limit=1)

        if isinstance(page, base.ErrorResponse) or not page.data:
            return None

        return page.data[0].id

    async def samples_page(
        self,
        subset: enums.SampleSubsets | str = enums.SampleSubsets.OWNED,
        limit: int = 20,
        offset: str | None = None,
    ) -> base.SamplesPage | base.ErrorResponse:
        """Get a single page of samples (GET /v0/samples).

        Parameters
        ----------
        subset : enums.SampleSubsets | str, optional
            ``owned`` (your samples), ``org`` (your organization's), or ``public``.
        limit : int, optional
            The page size, at most ``MAX_PAGE_SIZE``. By default 20.
        offset : str | None, optional
            The ``next`` value of the previous page.
        """

        params = {"subset": _value(subset), "limit": min(limit, MAX_PAGE_SIZE), "offset": offset}
        return await self._model(base.SamplesPage, "get", "/v0/samples", params=params)

    async def search_page(
        self, query: str, limit: int = 20, offset: str | None = None
    ) -> base.SamplesPage | base.ErrorResponse:
        """Get a single page of search results (GET /v0/search).

        See the Hatching Triage `docs`_ for how to search.

        .. _docs: https://tria.ge/docs/cloud-api/search/
        """

        params = {"query": query, "limit": min(limit, MAX_PAGE_SIZE), "offset": offset}
        return await self._model(base.SamplesPage, "get", "/v0/search", params=params)

    async def _pages(self, getpage, limit: int) -> AsyncIterator[base.SamplesPage | base.ErrorResponse]:
        """Yield pages from ``getpage(limit, offset)`` until ``limit`` items (0 is no limit)."""

        offset = None
        count = 0
        while True:
            size = MAX_PAGE_SIZE if not limit else min(MAX_PAGE_SIZE, limit - count)
            page = await getpage(size, offset)
            yield page
            if isinstance(page, base.ErrorResponse) or not page.data:
                return
            count += len(page.data)
            if not page.next or (limit and count >= limit):
                return
            offset = page.next

    async def _iter(self, getpage, limit: int) -> AsyncIterator[base.SampleInfo]:
        count = 0
        async for page in self._pages(getpage, limit):
            if isinstance(page, base.ErrorResponse):
                raise api_error(page)
            for item in page.data:
                yield item
                count += 1
                if limit and count >= limit:
                    return

    async def _list(self, getpage, limit: int) -> list[base.SampleInfo] | base.ErrorResponse:
        ret = []
        async for page in self._pages(getpage, limit):
            if isinstance(page, base.ErrorResponse):
                return page
            ret.extend(page.data)
        return ret[:limit] if limit else ret

    async def iter_samples(
        self, subset: enums.SampleSubsets | str = enums.SampleSubsets.OWNED, limit: int = 20
    ) -> AsyncIterator[base.SampleInfo]:
        """Yield up to ``limit`` samples (0 for all of them) from a subset, newest first."""

        async def getpage(size, offset):
            return await self.samples_page(subset, limit=size, offset=offset)

        async for item in self._iter(getpage, limit):
            yield item

    async def get_samples(
        self, subset: enums.SampleSubsets | str = enums.SampleSubsets.OWNED, limit: int = 20
    ) -> list[base.SampleInfo] | base.ErrorResponse:
        """Return up to ``limit`` samples (0 for all of them) from a subset, newest first."""

        async def getpage(size, offset):
            return await self.samples_page(subset, limit=size, offset=offset)

        return await self._list(getpage, limit)

    async def iter_search(self, query: str, limit: int = 20) -> AsyncIterator[base.SampleInfo]:
        """Yield up to ``limit`` samples (0 for all of them) matching ``query``."""

        async def getpage(size, offset):
            return await self.search_page(query, limit=size, offset=offset)

        async for item in self._iter(getpage, limit):
            yield item

    async def search(
        self, query: str, limit: int = 20
    ) -> list[base.SamplesResponse] | base.ErrorResponse:
        """Search the Hatching Triage Sandbox for samples matching ``query``.

        See the Hatching Triage `docs`_ for how to search.

        Parameters
        ----------
        query : str
            The query string to search for.
        limit : int, optional
            The most samples to return, pages through the results as needed.
            Use 0 for every result. By default 20.

        Returns
        -------
        list[base.SampleInfo]
            A list containing ``SampleInfo`` objects for each returned sample.

        .. _docs: https://tria.ge/docs/cloud-api/search/
        """

        async def getpage(size, offset):
            return await self.search_page(query, limit=size, offset=offset)

        return await self._list(getpage, limit)

    async def get_sample(self, sample: str) -> base.SampleInfo | base.ErrorResponse | None:
        """Get metadata about a sample by hash or sample ID.

        Parameters
        ----------
        sample : str
            The sample to get, this can be any of the following
            as the value is passed to ``sample_id`` if needed to find the ID::

                sample uuid, md5, sha1, sha2, ssdeep

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

        return await self._model(base.SampleInfo, "get", f"/v0/samples/{_seg(sample_id)}")

    async def delete_sample(self, sample: str) -> None | base.ErrorResponse:
        """Delete a sample (and its analyses) that you own."""

        sample_id = await self.norm_sample(sample)
        if sample_id is None:
            return None
        return await self._empty("delete", f"/v0/samples/{_seg(sample_id)}")

    async def set_sample_profile(
        self,
        sample: str,
        profiles: list[base.HatchingProfileSubmission | dict] | None = None,
        auto: bool = False,
        pick: list[str] | None = None,
    ) -> None | base.ErrorResponse:
        """Pick the profiles for a sample that was submitted with ``interactive=True``.

        Parameters
        ----------
        sample : str
            The sample ID (in the ``static_analysis`` status).
        profiles : list, optional
            The profiles to run, ex. ``[{"profile": "w10", "pick": "file1.exe"}]``.
        auto : bool, optional
            Let the sandbox pick the profiles, by default False.
        pick : list[str] | None, optional
            With ``auto``, the files (in an archive) to analyze.
        """

        if auto:
            body = {"auto": True, "pick": list(pick or [])}
        else:
            body = {
                "auto": False,
                "profiles": [
                    p.model_dump(exclude_none=True, mode="json")
                    if isinstance(p, base.TriageModel) else p
                    for p in profiles or []
                ],
            }
        return await self._empty("post", f"/v0/samples/{_seg(sample)}/profile", json=body)

    async def sample_events(self, sample: str) -> AsyncIterator[base.SampleInfo]:
        """Stream a sample's status changes until its analysis finishes (GET /samples/{id}/events)."""

        async for event in self._iter_json_lines(f"/v0/samples/{_seg(sample)}/events"):
            yield self.convert_resp(base.SampleInfo, None, event)

    async def samples_events(self) -> AsyncIterator[base.SampleInfo]:
        """Stream the status changes of all your running samples (GET /samples/events)."""

        async for event in self._iter_json_lines("/v0/samples/events"):
            yield self.convert_resp(base.SampleInfo, None, event)

    async def _submit_sample(
        self,
        json: dict | None = None,
        data: aiohttp.FormData | None = None,
    ):
        """Actually make the submit sample HTTP request."""

        resp, resp_dict = await self._request("post", "/v0/samples", json=json, data=data)
        return resp, resp_dict

    async def _submit_fetch(
        self,
        submit_req: base.SubmissionRequest,
    ):
        """Submit a file hosted at a URL for the sandbox to download and analyze."""

        return await self._submit_sample(json=submit_req.model_dump(exclude_none=True, mode="json"))

    async def _submit_file(
        self,
        submit_req: base.SubmissionRequest,
        sample: bytes | pathlib.Path | str,
    ):
        """Submit a file to the sandbox for analysis."""

        if isinstance(sample, (bytes, bytearray)):
            if not submit_req.target:
                fhash = hashlib.md5(sample).hexdigest()
                raise errors.PyHatchingValueError(
                    f"Must specify a filename (target) when submitting bytes ({fhash})"
                )
            byts = bytes(sample)
            filename = submit_req.target
        else:
            path = os.path.expandvars(os.path.expanduser(str(sample)))
            try:
                with open(path, "rb") as fd:
                    byts = fd.read()
            except OSError as err:
                raise errors.PyHatchingFileError(
                    f"Unable to read {sample}: {err}"
                ) from err
            filename = submit_req.target or os.path.basename(path)

        form = aiohttp.FormData()
        form.add_field("_json", submit_req.model_dump_json(exclude_none=True))
        form.add_field(
            "file", byts, filename=filename, content_type="application/octet-stream"
        )

        return await self._submit_sample(data=form)

    async def submit_sample(
        self,
        submit_req: base.SubmissionRequest,
        sample: bytes | pathlib.Path | str | None = None,
    ) -> base.SamplesResponse | base.ErrorResponse:
        """Submit a sample to the sandbox based on the given ``SubmissionRequest``.

        Parameters
        ----------
        submit_req : base.SubmissionRequest
            The object used to make the request - see this object for details.
        sample : bytes | pathlib.Path | str
            The local file path or raw bytes to submit, for ``file`` submissions.
            ``submit_req.target`` must be set to a filename when passing bytes.

        Returns
        -------
        base.SamplesResponse
            If successful, the newly created sample object.
        base.ErrorResponse
            If the API reports an error with the submission.
        """

        kind = _value(submit_req.kind)
        if kind == "file":
            if sample is None:
                raise errors.PyHatchingValueError(
                    "No file specified for file based submission."
                )
            resp, resp_dict = await self._submit_file(submit_req, sample)
        else:
            if submit_req.url is None:
                raise errors.PyHatchingValueError(
                    f"No URL specified for {kind} based submission."
                )
            resp, resp_dict = await self._submit_fetch(submit_req)

        return self.convert_resp(base.SamplesResponse, resp, resp_dict)

    # ---- Reports ----

    async def overview(self, sample: str) -> base.OverviewReport | base.ErrorResponse | None:
        """Return a sample's Overview Report (GET /v1/samples/{id}/overview.json).

        Parameters
        ----------
        sample : str
            The sample, this can be any of the following
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

        return await self._model(
            base.OverviewReport, "get", f"/v1/samples/{_seg(sample_id)}/overview.json"
        )

    async def static_report(self, sample: str) -> base.StaticReport | base.ErrorResponse | None:
        """Return a sample's static analysis report (GET /v0/samples/{id}/reports/static)."""

        sample_id = await self.norm_sample(sample)
        if sample_id is None:
            return None

        return await self._model(
            base.StaticReport, "get", f"/v0/samples/{_seg(sample_id)}/reports/static"
        )

    async def task_report(
        self, sample: str, task: str
    ) -> base.TriageReport | base.ErrorResponse | None:
        """Return a task's dynamic analysis report (GET /v0/samples/{id}/{task}/report_triage.json).

        ``task`` is a task name like ``behavioral1`` (or the full ``<sample>-behavioral1``).
        """

        sample_id = await self.norm_sample(sample)
        if sample_id is None:
            return None

        task = self._task(sample_id, task)
        return await self._model(
            base.TriageReport,
            "get",
            f"/v0/samples/{_seg(sample_id)}/{_seg(task)}/report_triage.json",
        )

    async def sample_summary(self, sample: str) -> base.SampleSummary | base.ErrorResponse | None:
        """Return a short summary of a sample and its tasks (GET /v0/samples/{id}/summary)."""

        sample_id = await self.norm_sample(sample)
        if sample_id is None:
            return None

        return await self._model(base.SampleSummary, "get", f"/v0/samples/{_seg(sample_id)}/summary")

    async def urlscan_report(
        self, sample: str, task: str = "urlscan1"
    ) -> dict | base.ErrorResponse | None:
        """Return a task's UrlScan report (GET /v0/samples/{id}/{task}/report_urlscan.json).

        URL samples only. The report is returned as a dict because Hatching documents
        its structure as externally managed and subject to change.
        """

        sample_id = await self.norm_sample(sample)
        if sample_id is None:
            return None

        task = self._task(sample_id, task)
        resp, resp_dict = await self._request(
            "get", f"/v0/samples/{_seg(sample_id)}/{_seg(task)}/report_urlscan.json"
        )
        if isinstance(resp_dict, dict) and "error" in resp_dict and resp.status >= 400:
            return self.convert_resp(base.ErrorResponse, resp, resp_dict)
        return resp_dict

    async def magic_token(self, sample: str) -> str | base.ErrorResponse | None:
        """Return a sample's magic link token (GET /v0/samples/{id}/magic).

        The token builds a shareable link: ``{url}/{sample_id}/magic/{token}``.
        Magic links must be enabled for your organization, see ``set_magic_link``.
        """

        sample_id = await self.norm_sample(sample)
        if sample_id is None:
            return None

        resp, _ = await self._request("get", f"/v0/samples/{_seg(sample_id)}/magic", raw=True)
        if resp.status >= 400:
            err = await self._raw_error(resp)
            if self.raise_on_api_err:
                raise api_error(err)
            return err
        try:
            text = await resp.text()
        except (aiohttp.ClientError, TimeoutError) as exc:
            raise errors.PyHatchingRequestError(
                f"Error reading the magic token from Hatching Triage: {exc}"
            ) from exc
        finally:
            resp.release()
        try:
            obj = jsonlib.loads(text)
        except ValueError:
            obj = text
        if isinstance(obj, dict):
            return obj.get("token") or obj.get("magic_token") or obj.get("magic")
        return str(obj).strip() or None

    async def kernel_report(
        self, sample: str, task: str, log: enums.KernelLogs | str | None = None
    ) -> AsyncIterator[dict]:
        """Yield the kernel monitor events of a task (GET /v0/samples/{id}/{task}/logs/{log}.json).

        Parameters
        ----------
        sample : str
            The sample ID.
        task : str
            The task name, ex. ``behavioral1``.
        log : enums.KernelLogs | str | None, optional
            The log's name (ex. ``onemon``). By default the overview report is used to
            pick the log for the task's platform.
        """

        sample = await self._stream_sample(sample)
        task = self._task(sample, task)
        if log is None:
            report = await self.overview(sample)
            if isinstance(report, base.ErrorResponse):
                raise api_error(report)
            for summary in (report.tasks if report is not None else None) or []:
                if self._task(sample, summary.name or "") == task:
                    log = kernel_log_name(summary)
                    break
            else:
                raise errors.PyHatchingValueError(f"Task {task} does not exist for {sample}.")

        uri = f"/v0/samples/{_seg(sample)}/{_seg(task)}/logs/{_seg(_value(log))}.json"
        async for event in self._iter_json_lines(uri):
            yield event

    # ---- Files ----

    def _file_uri(self, sample_id: str, task: str, filename: str) -> str:
        task = self._task(sample_id, task)
        return f"/v0/samples/{_seg(sample_id)}/{_seg(task)}/{quote(filename.lstrip('/'), safe='/')}"

    async def download_sample(self, sample: str) -> bytes | None:
        """Download a sample's bytes by the given ID.

        Parameters
        ----------
        sample : str
            The sample to download, this can be any of the following
            as the value is passed to ``sample_id`` if needed to find the ID::

                sample uuid, md5, sha1, sha2, ssdeep

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

        return await self._bytes(f"/v0/samples/{_seg(sample_id)}/sample")

    async def iter_sample(self, sample: str, chunk_size: int = CHUNK_SIZE) -> AsyncIterator[bytes]:
        """Download a sample in chunks."""

        sample = await self._stream_sample(sample)
        async for chunk in self._iter_bytes(f"/v0/samples/{_seg(sample)}/sample", chunk_size):
            yield chunk

    async def task_file(self, sample: str, task: str, filename: str) -> bytes | None:
        """Download a file from a task (GET /v0/samples/{id}/{task}/{filename}).

        ``filename`` is a file the task produced, ex. ``dump.pcap``, ``dump.pcapng``,
        ``screenshot.png`` (``urlscan1`` tasks), or the ``name`` of a file or memory dump
        listed in a task report's ``dumped`` section (ex. ``files/file.exe``).
        """

        sample_id = await self.norm_sample(sample)
        if sample_id is None:
            return None

        return await self._bytes(self._file_uri(sample_id, task, filename))

    async def iter_task_file(
        self, sample: str, task: str, filename: str, chunk_size: int = CHUNK_SIZE
    ) -> AsyncIterator[bytes]:
        """Download a file from a task in chunks, see ``task_file``."""

        sample = await self._stream_sample(sample)
        async for chunk in self._iter_bytes(self._file_uri(sample, task, filename), chunk_size):
            yield chunk

    async def task_pcap(self, sample: str, task: str, pcapng: bool = False) -> bytes | None:
        """Download a task's network capture, as a pcap or (with ``pcapng``) a pcapng."""

        return await self.task_file(sample, task, "dump.pcapng" if pcapng else "dump.pcap")

    async def task_screenshot(self, sample: str, task: str = "urlscan1") -> bytes | None:
        """Download a task's screenshot (GET /v0/samples/{id}/{task}/screenshot.png).

        URL samples only.
        """

        return await self.task_file(sample, task, "screenshot.png")

    def _archive_uri(self, sample_id: str, fmt: enums.ArchiveFormats | str) -> str:
        fmt = _value(fmt)
        if fmt not in ("tar", "zip"):
            raise errors.PyHatchingValueError(f"Unknown archive format: {fmt}")
        suffix = ".zip" if fmt == "zip" else ""
        return f"/v0/samples/{_seg(sample_id)}/archive{suffix}"

    async def sample_archive(
        self, sample: str, fmt: enums.ArchiveFormats | str = enums.ArchiveFormats.TAR
    ) -> bytes | None:
        """Download an archive (tar or zip) of a sample's reports and files."""

        sample_id = await self.norm_sample(sample)
        if sample_id is None:
            return None

        return await self._bytes(self._archive_uri(sample_id, fmt))

    async def iter_sample_archive(
        self,
        sample: str,
        fmt: enums.ArchiveFormats | str = enums.ArchiveFormats.TAR,
        chunk_size: int = CHUNK_SIZE,
    ) -> AsyncIterator[bytes]:
        """Download an archive of a sample in chunks, see ``sample_archive``."""

        sample = await self._stream_sample(sample)
        async for chunk in self._iter_bytes(self._archive_uri(sample, fmt), chunk_size):
            yield chunk

    # ---- Resources, geolocations, and stats ----

    async def get_resources(self) -> list[base.ResourceGroup] | base.ErrorResponse:
        """List the available analysis environments (GET /v0/resources).

        A resource is an analysis environment for a specific OS, language, and
        other specifics. Its ``tags`` can be used in profiles and submissions.
        """

        return await self._model(base.ResourceGroup, "get", "/v0/resources")

    async def get_geolocations(self) -> list[base.GeolocationGroup] | base.ErrorResponse:
        """List the regions VPN-routed analyses can exit from (GET /v0/geolocations)."""

        return await self._model(base.GeolocationGroup, "get", "/v0/geolocations")

    async def user_stats(self) -> base.UsageStats | base.ErrorResponse:
        """Return your usage statistics (GET /v0/stats/user)."""

        return await self._model(base.UsageStats, "get", "/v0/stats/user")

    async def org_stats(self) -> base.UsageStats | base.ErrorResponse:
        """Return your organization's usage statistics (GET /v0/stats/org)."""

        return await self._model(base.UsageStats, "get", "/v0/stats/org")

    # ---- Organization settings ----

    async def get_org_settings(self) -> base.OrgSettings | base.ErrorResponse:
        """Return your organization's settings (GET /v0/org/settings).

        Requires the ``manage_company`` permission.
        """

        return await self._model(base.OrgSettings, "get", "/v0/org/settings")

    async def set_magic_link(self, enabled: bool) -> None | base.ErrorResponse:
        """Enable or disable magic link creation (PUT /v0/org/settings/magic).

        Requires the ``manage_company`` permission. See ``magic_token``.
        """

        return await self._empty("put", "/v0/org/settings/magic", json={"enabled": enabled})

    # ---- Profiles ----

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

        return await self._model(
            base.HatchingProfileResponse, "get", f"/v0/profiles/{_seg(profile_id)}"
        )

    async def get_profiles(
        self, limit: int | None = None, offset: int | str | None = None
    ) -> list[base.HatchingProfileResponse] | base.ErrorResponse:
        """Get all sandbox analysis profiles for your account.

        Returns
        -------
        list[base.HatchingProfileResponse]
            If successful, the requested sandbox profiles.
        base.ErrorResponse
            If there was an error.
        """

        return await self._model(
            base.HatchingProfileResponse,
            "get",
            "/v0/profiles",
            params={"limit": limit, "offset": offset},
        )

    async def submit_profile(
        self,
        name: str,
        tags: list[str],
        timeout: int | None = None,
        network: enums.ProfileNetworkOptions | str | None = None,
        geolocation: str | None = None,
    ) -> base.HatchingProfileResponse | base.ErrorResponse:
        """Add a new sandbox analysis profile to your account.

        Parameters
        ----------
        name : str
            The name of the new profile, must not exist already.
        tags : list[str]
            The tags that match this profile to samples, ex. ``["windows10"]``.
        timeout : int
            The profiles timeout length in seconds.
        network : enums.ProfileNetworkOptions
            The network option for this analysis profile.
        geolocation : str
            The VPN region to exit from (see ``get_geolocations``), requires
            ``network`` to be ``vpn``.

        Returns
        -------
        base.HatchingProfileResponse | base.ErrorResponse
            The new profile, or the error.
        """

        data = {"name": name, "tags": list(tags or []), "timeout": timeout,
                "network": _value(network), "geolocation": geolocation}
        data = {k: v for k, v in data.items() if v is not None}

        resp, resp_dict = await self._request("post", "/v0/profiles", json=data)
        if not resp_dict and resp.status < 400:
            # Some API versions return an empty object instead of the new profile.
            return base.HatchingProfileResponse(resp_obj=resp, **data)
        return self.convert_resp(base.HatchingProfileResponse, resp, resp_dict)

    async def update_profile(  # pylint: disable=R0913
        self,
        tags: list[str],
        timeout: int,
        network: enums.ProfileNetworkOptions | str,
        name: str,
        profile_id: str,
        geolocation: str | None = None,
    ) -> None | base.ErrorResponse:
        """Update the given profile (PUT /v0/profiles/{id}).

        See `profile docs`_ for how this endpoint behaves, the stored profile is
        overwritten so all args (except ``geolocation``) are required.

        Parameters
        ----------
        tags : list[str]
            The tags that match this profile to samples.
        timeout : int
            The profiles timeout length in seconds.
        network : enums.ProfileNetworkOptions
            The network option for this analysis profile.
        name : str
            The (new) name of the profile.
        profile_id : str
            The ID or current name of the profile to update.
        geolocation : str, optional
            The VPN region to exit from, requires ``network`` to be ``vpn``.

        Returns
        -------
        None | base.ErrorResponse
            None if successful, otherwise a ``base.ErrorResponse``.

        .. _profile docs: https://tria.ge/docs/cloud-api/profiles/
        """

        data = {"name": name, "tags": list(tags or []), "timeout": timeout,
                "network": _value(network), "geolocation": geolocation}

        return await self._empty(
            "put",
            f"/v0/profiles/{_seg(profile_id)}",
            json={k: v for k, v in data.items() if v is not None},
        )

    async def delete_profile(self, profile_id: str) -> None | base.ErrorResponse:
        """Delete a profile by ID or name."""

        return await self._empty("delete", f"/v0/profiles/{_seg(profile_id)}")

    # ---- Yara ----

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

        return await self._model(base.YaraRule, "get", f"/v0/yara/{_seg(rule_name)}")

    async def get_rules(self) -> base.YaraRules | base.ErrorResponse:
        """Get all Yara rules tied to your account.

        Returns
        -------
        base.YaraRules
            If successful, the returned Yara rules.
        """

        return await self._model(base.YaraRules, "get", "/v0/yara")

    async def _write_rule(self, method: str, name: str, contents: str):
        """A generic method to create/update a yara rule."""

        data = {"name": name, "rule": contents}

        if method == "put":
            uri = f"/v0/yara/{_seg(name)}"
        else:
            uri = "/v0/yara"

        return await self._empty(method, uri, json=data)

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

    async def delete_rule(self, name: str) -> base.ErrorResponse | None:
        """Delete a Yara rule by name."""

        return await self._empty("delete", f"/v0/yara/{_seg(name)}")

    # ---- Users (private instances) ----

    async def get_users(
        self, limit: int | None = None, offset: int | str | None = None
    ) -> list[base.User] | base.ErrorResponse:
        """List the users of your company (requires admin permissions)."""

        return await self._model(
            base.User, "get", "/v0/users", params={"limit": limit, "offset": offset}
        )

    async def get_user(self, user_id: str) -> base.User | base.ErrorResponse:
        """Get a user by ID (requires admin permissions)."""

        return await self._model(base.User, "get", f"/v0/users/{_seg(user_id)}")

    async def create_user(  # pylint: disable=R0913
        self,
        username: str | None = None,
        email: str | None = None,
        password: str | None = None,
        first_name: str | None = None,
        last_name: str | None = None,
        permissions: list[str] | None = None,
        name: str | None = None,
        role: str | None = None,
        email_confirmed: bool | None = None,
    ) -> base.User | base.ErrorResponse:
        """Create a user in your company (requires the manage_company permission).

        The API takes either a ``username`` (which can't contain ``@``) or an
        ``email``, not both. ``first_name`` and ``last_name`` are deprecated by
        the API in favor of ``name``.
        """

        if not username and not email:
            raise errors.PyHatchingValueError("A username or email is required.")

        data = {
            "username": username,
            "email": email,
            "email_confirmed": email_confirmed,
            "password": password,
            "name": name,
            "first_name": first_name,
            "last_name": last_name,
            "role": role,
            "permissions": permissions,
        }
        return await self._model(
            base.User, "post", "/v0/users", json={k: v for k, v in data.items() if v is not None}
        )

    async def delete_user(self, user_id: str) -> None | base.ErrorResponse:
        """Delete a user (requires admin permissions)."""

        return await self._empty("delete", f"/v0/users/{_seg(user_id)}")

    async def get_user_apikeys(self, user_id: str) -> list[base.ApiKey] | base.ErrorResponse:
        """List the API keys of a user."""

        return await self._model(base.ApiKey, "get", f"/v0/users/{_seg(user_id)}/apikeys")

    async def create_user_apikey(self, user_id: str, name: str) -> base.ApiKey | base.ErrorResponse:
        """Create a new API key for a user."""

        return await self._model(
            base.ApiKey, "post", f"/v0/users/{_seg(user_id)}/apikeys", json={"name": name}
        )

    async def delete_user_apikey(self, user_id: str, name: str) -> None | base.ErrorResponse:
        """Delete an API key of a user by its name."""

        return await self._empty("delete", f"/v0/users/{_seg(user_id)}/apikeys/{_seg(name)}")
