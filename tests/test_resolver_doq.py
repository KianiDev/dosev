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
        # Store the last created client so tests can verify
        mock._client = None

        class MockCM:
            def __init__(self, client):
                self.client = client
                mock._client = client
            async def __aenter__(self):
                return self.client
            async def __aexit__(self, *args):
                pass

        def side_effect(*args, **kwargs):
            return MockCM(MockQuicClient(closed=False))

        mock.side_effect = side_effect
        yield mock


@pytest.mark.asyncio
async def test_doq_connection_pool_reuse(resolver, mock_connect):
    dummy_response = b"\x00\x0d" + b"dummy_response"
    with patch("asyncio.wait_for", new=AsyncMock(return_value=dummy_response)):
        query = dns.message.make_query("example.com", "A").to_wire()
        upstream = resolver.upstreams[0]

        result1 = await resolver._forward_quic(query, upstream)
        assert result1 == b"dummy_response"
        assert mock_connect.call_count == 1

        result2 = await resolver._forward_quic(query, upstream)
        assert result2 == b"dummy_response"
        assert mock_connect.call_count == 1  # reused


@pytest.mark.asyncio
async def test_doq_connection_pool_closed_connection(resolver, mock_connect):
    # We need to simulate that the pool.get returns a closed client on the second call.
    # We'll patch the pool.get to return a closed client.
    client_open = MockQuicClient(closed=False)
    client_closed = MockQuicClient(closed=True)

    # Override the mock_connect to return different clients on each call
    clients = [client_open, MockQuicClient(closed=False)]
    def connect_side_effect(*args, **kwargs):
        class CM:
            def __init__(self, client):
                self.client = client
            async def __aenter__(self):
                return self.client
            async def __aexit__(self, *args):
                pass
        return CM(clients.pop(0))
    mock_connect.side_effect = connect_side_effect

    # Mock pool.get to return closed client on second call
    with patch.object(resolver._quic_pool, "get") as mock_pool_get:
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
            assert mock_connect.call_count == 2  # new connection created


@pytest.mark.asyncio
async def test_doq_connection_pool_handles_timeout(resolver, mock_connect):
    mock_client = MockQuicClient(closed=False)
    mock_connect.side_effect = lambda *args, **kwargs: type(
        "CM", (), {"__aenter__": AsyncMock(return_value=mock_client), "__aexit__": AsyncMock(return_value=None)}
    )()

    with patch("asyncio.wait_for", new=AsyncMock(side_effect=asyncio.TimeoutError)):
        query = dns.message.make_query("example.com", "A").to_wire()
        upstream = resolver.upstreams[0]

        with patch.object(resolver._quic_pool, "put") as mock_put:
            with pytest.raises(TimeoutError):
                await resolver._forward_quic(query, upstream)
            mock_put.assert_not_called()


@pytest.mark.asyncio
async def test_doq_pool_handles_connection_error_during_handshake(resolver, mock_connect):
    mock_client = MockQuicClient()
    mock_client._connected = False
    mock_connect.side_effect = lambda *args, **kwargs: type(
        "CM", (), {"__aenter__": AsyncMock(return_value=mock_client), "__aexit__": AsyncMock(return_value=None)}
    )()

    query = dns.message.make_query("example.com", "A").to_wire()
    upstream = resolver.upstreams[0]

    with patch.object(resolver._quic_pool, "put") as mock_put:
        with pytest.raises(ConnectionError):
            await resolver._forward_quic(query, upstream)
        mock_put.assert_not_called()