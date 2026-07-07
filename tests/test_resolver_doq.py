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
    """Mock aioquic.asyncio.client.connect to return a context manager that yields a MockQuicClient."""
    with patch("aioquic.asyncio.client.connect") as mock:
        # We'll set side_effect to a function that returns a custom context manager
        # This allows each test to define its own behavior by patching further.
        yield mock


@pytest.mark.asyncio
async def test_doq_connection_pool_reuse(resolver, mock_connect):
    """Verify that DoQ connections are reused from the pool."""
    # Create a mock client
    mock_client = MockQuicClient(closed=False)
    mock_client.wait_connected = AsyncMock(return_value=None)

    # Define a custom context manager that yields this client
    class CM:
        async def __aenter__(self):
            return mock_client
        async def __aexit__(self, *args):
            pass

    # Override the side_effect to return our CM
    mock_connect.side_effect = lambda *args, **kwargs: CM()

    dummy_response = b"\x00\x0d" + b"dummy_response"
    with patch("asyncio.wait_for", new=AsyncMock(return_value=dummy_response)):
        query = dns.message.make_query("example.com", "A").to_wire()
        upstream = resolver.upstreams[0]

        result1 = await resolver._forward_quic(query, upstream)
        assert result1 == b"dummy_response"
        assert mock_connect.call_count == 1

        result2 = await resolver._forward_quic(query, upstream)
        assert result2 == b"dummy_response"
        assert mock_connect.call_count == 1  # Reused


@pytest.mark.asyncio
async def test_doq_connection_pool_closed_connection(resolver, mock_connect):
    """If a pooled connection is closed, a new one should be created."""
    # Create two clients: one open, one closed
    client_open = MockQuicClient(closed=False)
    client_open.wait_connected = AsyncMock(return_value=None)

    client_closed = MockQuicClient(closed=True)
    client_closed.wait_connected = AsyncMock(return_value=None)  # Shouldn't be called

    # Define a custom context manager that yields a client from a list
    clients = [client_open, client_closed]

    class CM:
        def __init__(self, client):
            self.client = client
        async def __aenter__(self):
            return self.client
        async def __aexit__(self, *args):
            pass

    # Override side_effect to return a new context manager each time
    def connect_side_effect(*args, **kwargs):
        return CM(clients.pop(0) if clients else MockQuicClient(closed=False))
    mock_connect.side_effect = connect_side_effect

    # Mock pool.get to return closed client on second call
    with patch.object(resolver._quic_pool, "get") as mock_pool_get:
        # First call: no pooled client (None), second call: closed client
        mock_pool_get.side_effect = [None, client_closed]

        dummy_response = b"\x00\x0d" + b"dummy_response"
        with patch("asyncio.wait_for", new=AsyncMock(return_value=dummy_response)):
            query = dns.message.make_query("example.com", "A").to_wire()
            upstream = resolver.upstreams[0]

            result1 = await resolver._forward_quic(query, upstream)
            assert result1 == b"dummy_response"
            assert mock_connect.call_count == 1

            result2 = await resolver._forward_quic(query, upstream)
            assert result2 == b"dummy_response"
            assert mock_connect.call_count == 2  # New connection created


@pytest.mark.asyncio
async def test_doq_connection_pool_handles_timeout(resolver, mock_connect):
    """If a DoQ query times out, the connection should not be put back into the pool."""
    mock_client = MockQuicClient(closed=False)
    mock_client.wait_connected = AsyncMock(return_value=None)

    class CM:
        async def __aenter__(self):
            return mock_client
        async def __aexit__(self, *args):
            pass

    mock_connect.side_effect = lambda *args, **kwargs: CM()

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
    mock_client = MockQuicClient()
    mock_client._connected = False
    mock_client.wait_connected = AsyncMock(side_effect=ConnectionError("Connection failed"))

    class CM:
        async def __aenter__(self):
            return mock_client
        async def __aexit__(self, *args):
            pass

    mock_connect.side_effect = lambda *args, **kwargs: CM()

    query = dns.message.make_query("example.com", "A").to_wire()
    upstream = resolver.upstreams[0]

    with patch.object(resolver._quic_pool, "put") as mock_put:
        with pytest.raises(ConnectionError):
            await resolver._forward_quic(query, upstream)
        mock_put.assert_not_called()