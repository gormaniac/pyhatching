"""Pyhatching helper functions."""

import re

from . import enums


MD5RE: re.Pattern = re.compile(r"^[a-fA-F0-9]{32}")
SHA1RE: re.Pattern = re.compile(r"^[a-fA-F0-9]{40}")
SHA2RE: re.Pattern = re.compile(r"^[a-fA-F0-9]{64}")
SHA5RE: re.Pattern = re.compile(r"^[a-fA-F0-9]{128}")

HASHRE: re.Pattern = re.compile(
    r"^[a-fA-F0-9]{128}|^[a-fA-F0-9]{64}|^[a-fA-F0-9]{40}|^[a-fA-F0-9]{32}"
)


def is_hash(input_hash: str) -> bool:
    """
    True if input_hash is one of the following hash types: md5, sha1, sha256, sha512
    """

    if HASHRE.search(input_hash):
        return True
    return False


def hash_type(input_hash: str) -> enums.HashPrefixes | None:
    """Determine the type of a given hash.

    Supports: md5, sha1, sha256, sha512

    Parameters
    ----------
    input_hash : str
        A hash of one of the following types: md5, sha1, sha256, sha512

    Returns
    -------
    enums.HashPrefixes | None
        Either the name of the hash type or None if the input is not a hash.
    """

    if SHA5RE.search(input_hash):
        return enums.HashPrefixes.SHA5.value
    if SHA2RE.search(input_hash):
        return enums.HashPrefixes.SHA2.value
    if SHA1RE.search(input_hash):
        return enums.HashPrefixes.SHA1.value
    if MD5RE.search(input_hash):
        return enums.HashPrefixes.MD5.value

    return None
