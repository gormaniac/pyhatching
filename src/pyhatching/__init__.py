"""Async client to interact with the Hatching Triage Sandbox.

Not a complete client - this library focuses on common use cases.

All client calls return objects (see `pyhatching.base`) instead of dicts,
unless bytes makes more sense for the endpoint (samples, pcaps).
"""

VERSION = "0.0.1"
