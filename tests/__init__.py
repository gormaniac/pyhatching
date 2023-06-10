"""pytest suite for pyhatching."""

import os
import pytest


@pytest.fixture
def token():
    """The API token to use while testing."""

    return os.environ["HATCHING_TOKEN"]
