"""Async client to interact with the Hatching Triage Sandbox.

Not a complete client - this library focuses on common use cases.

All client calls return objects (see `pyhatching.base`) instead of dicts,
unless bytes makes more sense for the endpoint (samples, pcaps).
"""

__version__ = "0.0.1"
"""The version of pyhatching."""

BASE_URL = "https://tria.ge/api/v0/"
"""The default URL for requests - the public/free version."""
