"""
Tests for DoQ connection pooling.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

import dns.message
import dns.rdatatype

from dosev.resolver import DNSResolver


class MockQuicClient:
    """Mock aioquic client for testing."""
    def __init__(self, closed=False):
        self._quic = MagicMock()
        self._quic.closed = closed
        self._quic.get_next_available_stream_id = MagicMock(return_value=0)
        self._quic.send_stream_data = MagicMock()
        self.transmit = MagicMock()
        self._pending = {}
        self._connected = True
        self.close = MagicMock()
        self._cm = None

    async def wait_connected(self):
        if not self._connected:
            raise ConnectionError("Connection failed")
        return True


@pytest.fixture
def resolver():
    return DNSResolver(upstreams=[{"address": "example.com", "protocol": "quic", "port": 853}])


@pytest.fixture
def mock_connect():
    """Mock aioquic.asyncio.client.connect to return a context manager."""
    with patch("aioquic.asyncio.client.connect") as mock:
        class MockCM:
            def __init__(self, client):
                self.client = client
            async def __aenter__(self):
                return self.client
            async def __aexit__(self, *args):
                pass
        # We'll not set side_effect here; tests will set as needed
        yield mock


@pytest.mark.asyncio
async def test_doq_connection_pool_reuse(resolver, mock_connect):
    """Verify that DoQ connections are reused from the pool."""
    # Create a mock client that will be returned by the first connect call
    mock_client = MockQuicClient(closed=False)
    mock_client.wait_connected = AsyncMock()
    mock_client._quic.get_next_available_stream_id = MagicMock(return_value=0)
    mock_client._quic.send_stream_data = MagicMock()
    mock_client.transmit = MagicMock()

    # Patch the connect to return the mock client
    class CM:
        async def __aenter__(self):
            return mock_client
        async def __aexit__(self, *args):
            pass
    mock_connect.return_value = CM()

    dummy_response = b"\x00\x0d" + b"dummy_response"
    with patch("asyncio.wait_for", new=AsyncMock(return_value=dummy_response)):
        query = dns.message.make_query("example.com", "A").to_wire()
        upstream = resolver.upstreams[0]

        result1 = await resolver._forward_quic(query, upstream)
        assert result1 == b"dummy_response"
        assert mock_connect.call_count == 1

        # Second call should reuse the same client (no new connect)
        result2 = await resolver._forward_quic(query, upstream)
        assert result2 == b"dummy_response"
        assert mock_connect.call_count == 1


@pytest.mark.asyncio
async def test_doq_connection_pool_closed_connection(resolver, mock_connect):
    """If a pooled connection is closed, a new one should be created."""
    client_open = MockQuicClient(closed=False)
    client_closed = MockQuicClient(closed=True)

    # First call: no pooled connection, create a new one (open)
    # Second call: pool.get returns the closed client, so it will be discarded and a new one created
    # We'll set up the mock to return the closed client on the second call.

    # Patch the pool.get to return the closed client on second call
    with patch.object(resolver._quic_pool, "get") as mock_pool_get:
        mock_pool_get.side_effect = [None, client_closed]

        # Mock connect to return a new client each time
        class CM:
            def __init__(self, client):
                self.client = client
            async def __aenter__(self):
                return self.client
            async def __aexit__(self, *args):
                pass

        # We'll create a simple counter to return different clients
        clients = [client_open, MockQuicClient(closed=False)]
        def connect_side_effect(*args, **kwargs):
            return CM(clients.pop(0))
        mock_connect.side_effect = connect_side_effect

        dummy_response = b"\x00\x0d" + b"dummy_response"
        with patch("asyncio.wait_for", new=AsyncMock(return_value=dummy_response)):
            query = dns.message.make_query("example.com", "A").to_wire()
            upstream = resolver.upstreams[0]

            result1 = await resolver._forward_quic(query, upstream)
            assert result1 == b"dummy_response"
            assert mock_connect.call_count == 1

            result2 = await resolver._forward_quic(query, upstream)
            assert result2 == b"dummy_response"
            assert mock_connect.call_count == 2


@pytest.mark.asyncio
async def test_doq_connection_pool_handles_timeout(resolver, mock_connect):
    """If a DoQ query times out, the connection should not be put back into the pool."""
    mock_client = MockQuicClient(closed=False)
    mock_client.wait_connected = AsyncMock()
    class CM:
        async def __aenter__(self):
            return mock_client
        async def __aexit__(self, *args):
            pass
    mock_connect.return_value = CM()

    with patch("asyncio.wait_for", new=AsyncMock(side_effect=asyncio.TimeoutError)):
        query = dns.message.make_query("example.com", "A").to_wire()
        upstream = resolver.upstreams[0]

        with patch.object(resolver._quic_pool, "put") as mock_put:
            with pytest.raises(TimeoutError):
                await resolver._forward_quic(query, upstream)
            mock_put.assert_not_called()


@pytest.mark.asyncio
async def test_doq_pool_handles_connection_error_during_handshake(resolver, mock_connect):
    """If the QUIC handshake fails (wait_connected raises), the connection should not be pooled."""
    client_fail = MockQuicClient()
    client_fail._connected = False
    class CM:
        async def __aenter__(self):
            return client_fail
        async def __aexit__(self, *args):
            pass
    mock_connect.return_value = CM()

    query = dns.message.make_query("example.com", "A").to_wire()
    upstream = resolver.upstreams[0]

    with patch.object(resolver._quic_pool, "put") as mock_put:
        with pytest.raises(ConnectionError):
            await resolver._forward_quic(query, upstream)
        mock_put.assert_not_called()