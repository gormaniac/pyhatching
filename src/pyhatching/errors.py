class PyHatchingError(Exception):
    """An error in the pyhatching client."""


class PyHatchingRequestError(PyHatchingError):
    """An error making a pyhatching HTTP request."""


class PyHatchingParseError(PyHatchingError):
    """An error parsing a pyhatching HTTP response object."""
