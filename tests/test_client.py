"""Tests pyhatching.PyHatchingClient and some related functions."""


import aiohttp

import pyhatching
import pytest

from . import token


class TestClientInit:
    @pytest.mark.asyncio
    async def test_ctxmgr(self, token):
        async with pyhatching.PyHatchingClient(api_key=token) as client:
            await client.close()
            assert isinstance(client, pyhatching.PyHatchingClient)

    @pytest.mark.asyncio
    async def test_factory(self, token):
        # NOTE Lets test out all the args, add new ones here when added to factory.
        client = await pyhatching.new_client(
            api_key=token,
            url="http://testurl.local",
            timeout=100,
            raise_on_api_err=False,
        )
        await client.close()
        assert isinstance(client, pyhatching.PyHatchingClient)

    @pytest.mark.asyncio
    async def test_init(self, token):
        client = pyhatching.PyHatchingClient(api_key=token)
        assert isinstance(client, pyhatching.PyHatchingClient)
        await client.start()
        assert isinstance(client.session, aiohttp.ClientSession)
        await client.close()
        assert client.session.closed
