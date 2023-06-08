"""Errors for pyhatching."""

class PyHatchingError(Exception):
    """An error in the pyhatching client."""


class PyHatchingValidateError(PyHatchingError):
    """An error validating a pyhatching JSON response object."""


class PyHatchingRequestError(PyHatchingError):
    """An error making a pyhatching HTTP request."""


class PyHatchingApiError(PyHatchingRequestError):
    """The Hatching Triage API returned an error."""
