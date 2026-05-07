"""Tests for ``lumen_argus_core.http``."""

from __future__ import annotations

import asyncio
import ssl
import unittest

from lumen_argus_core.http import make_passthrough_session


class TestMakePassthroughSession(unittest.TestCase):
    """Helper owns the load-bearing ``auto_decompress=False`` invariant."""

    def test_auto_decompress_disabled(self):
        """``auto_decompress`` must be False — body bytes flow through verbatim."""

        async def go():
            async with make_passthrough_session(limit=10) as session:
                self.assertFalse(session.auto_decompress)

        asyncio.run(go())

    def test_connector_limit_applied(self):
        """``limit`` reaches the underlying TCPConnector."""

        async def go():
            async with make_passthrough_session(limit=42) as session:
                self.assertEqual(session.connector.limit, 42)

        asyncio.run(go())

    def test_ssl_default_uses_aiohttp_default_verification(self):
        """No ``ssl`` arg → connector keeps aiohttp default (TLS verify enabled)."""

        async def go():
            async with make_passthrough_session(limit=1) as session:
                # aiohttp's TCPConnector defaults ssl=True (verify enabled).
                self.assertIs(session.connector._ssl, True)

        asyncio.run(go())

    def test_ssl_false_disables_verification(self):
        """``ssl=False`` propagates to the connector (used for self-signed mitm)."""

        async def go():
            async with make_passthrough_session(limit=1, ssl=False) as session:
                self.assertEqual(session.connector._ssl, False)

        asyncio.run(go())

    def test_ssl_context_propagates(self):
        """A custom SSLContext reaches the connector unchanged."""
        ctx = ssl.create_default_context()

        async def go():
            async with make_passthrough_session(limit=1, ssl=ctx) as session:
                self.assertIs(session.connector._ssl, ctx)

        asyncio.run(go())


if __name__ == "__main__":
    unittest.main()
