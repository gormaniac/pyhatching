"""Errors for pyhatching."""

class PyHatchingError(Exception):
    """An error in the pyhatching library."""


class PyHatchingFileError(PyHatchingError, OSError):
    """An error occured while pyhatching was working with a file."""


class PyHatchingValueError(PyHatchingError, ValueError):
    """An unexpected value was encountered by pyhatching."""


class PyHatchingValidateError(PyHatchingError):
    """An error validating a pyhatching Pydantic object."""


class PyHatchingConnError(PyHatchingError):
    """An error occurred at some point during the connection/request to the sandbox.
    
    The base Exception to catch when there's any errors from the sandbox API,
    including when the response body cannot be cast to a dict, when the API
    itself reports an error with the request, or any HTTP errors that might be raised.
    """


class PyHatchingRequestError(PyHatchingConnError):
    """An error making a pyhatching HTTP request."""


class PyHatchingJsonError(PyHatchingRequestError):
    """The response body from the sandbox could not be cast to a dict."""


class PyHatchingApiError(PyHatchingConnError):
    """The Hatching Triage API returned an error.

    Attributes
    ----------
    status : int | None
        The HTTP status code of the response, if known.
    error : str | None
        The API's error name (ex. ``NOT_FOUND``), see ``enums.ErrorNames``.
    message : str | None
        The API's description of the error.
    """

    def __init__(
        self,
        mesg: str,
        status: int | None = None,
        error: str | None = None,
        message: str | None = None,
    ) -> None:
        super().__init__(mesg)
        self.status = status
        self.error = error
        self.message = message
