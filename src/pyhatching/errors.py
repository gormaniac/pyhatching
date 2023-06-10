"""Errors for pyhatching."""

class PyHatchingError(Exception):
    """An error in the pyhatching library."""


class PyHatchingValueError(PyHatchingError):
    """An unexpected value was encountered by pyhatching."""


class PyHatchingValidateError(PyHatchingError):
    """An error validating a pyhatching JSON response."""


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
    """The Hatching Triage API returned an error."""
