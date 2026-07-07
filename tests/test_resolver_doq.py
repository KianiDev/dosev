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


@pytest.mark.asyncio
async def test_doq_connection_pool_reuse(resolver):
    """Verify that DoQ connections are reused from the pool."""
    # Create a mock client
    mock_client = MockQuicClient(closed=False)
    mock_client.wait_connected = AsyncMock(return_value=None)

    class CM:
        async def __aenter__(self):
            return mock_client
        async def __aexit__(self, *args):
            pass

    # Patch connect at the correct import location
    with patch("aioquic.asyncio.connect", return_value=CM()) as mock_connect:
        # Build a valid DoQ response: length prefix + actual data
        response_data = b"dummy_response"
        prefixed_response = len(response_data).to_bytes(2, "big") + response_data
        with patch("asyncio.wait_for", new=AsyncMock(return_value=prefixed_response)):
            query = dns.message.make_query("example.com", "A").to_wire()
            upstream = resolver.upstreams[0]

            result1 = await resolver._forward_quic(query, upstream)
            assert result1 == response_data
            assert mock_connect.call_count == 1

            result2 = await resolver._forward_quic(query, upstream)
            assert result2 == response_data
            assert mock_connect.call_count == 1  # Reused


@pytest.mark.asyncio
async def test_doq_connection_pool_closed_connection(resolver):
    """If a pooled connection is closed, a new one should be created."""
    client_open = MockQuicClient(closed=False)
    client_open.wait_connected = AsyncMock(return_value=None)

    client_closed = MockQuicClient(closed=True)
    client_closed.wait_connected = AsyncMock(return_value=None)

    class CMOpen:
        async def __aenter__(self):
            return client_open
        async def __aexit__(self, *args):
            pass

    class CMClosed:
        async def __aenter__(self):
            return client_closed
        async def __aexit__(self, *args):
            pass

    connect_returns = [CMOpen(), CMClosed()]
    def connect_side_effect(*args, **kwargs):
        return connect_returns.pop(0)

    with patch("aioquic.asyncio.connect", side_effect=connect_side_effect) as mock_connect:
        with patch.object(resolver._quic_pool, "get") as mock_pool_get:
            mock_pool_get.side_effect = [None, client_closed]

            response_data = b"dummy_response"
            prefixed_response = len(response_data).to_bytes(2, "big") + response_data
            with patch("asyncio.wait_for", new=AsyncMock(return_value=prefixed_response)):
                query = dns.message.make_query("example.com", "A").to_wire()
                upstream = resolver.upstreams[0]

                result1 = await resolver._forward_quic(query, upstream)
                assert result1 == response_data
                assert mock_connect.call_count == 1

                result2 = await resolver._forward_quic(query, upstream)
                assert result2 == response_data
                assert mock_connect.call_count == 2  # New connection created


@pytest.mark.asyncio
async def test_doq_connection_pool_handles_timeout(resolver):
    """If a DoQ query times out, the connection should not be put back into the pool."""
    mock_client = MockQuicClient(closed=False)
    mock_client.wait_connected = AsyncMock(return_value=None)

    class CM:
        async def __aenter__(self):
            return mock_client
        async def __aexit__(self, *args):
            pass

    with patch("aioquic.asyncio.connect", return_value=CM()) as mock_connect:
        with patch("asyncio.wait_for", new=AsyncMock(side_effect=asyncio.TimeoutError)):
            query = dns.message.make_query("example.com", "A").to_wire()
            upstream = resolver.upstreams[0]

            with patch.object(resolver._quic_pool, "put") as mock_put:
                with pytest.raises(TimeoutError):
                    await resolver._forward_quic(query, upstream)
                mock_put.assert_not_called()


@pytest.mark.asyncio
async def test_doq_pool_handles_connection_error_during_handshake(resolver):
    """If the QUIC handshake fails (wait_connected raises), the connection should not be pooled."""
    mock_client = MockQuicClient()
    mock_client._connected = False
    mock_client.wait_connected = AsyncMock(side_effect=ConnectionError("Connection failed"))

    class CM:
        async def __aenter__(self):
            return mock_client
        async def __aexit__(self, *args):
            pass

    with patch("aioquic.asyncio.connect", return_value=CM()) as mock_connect:
        query = dns.message.make_query("example.com", "A").to_wire()
        upstream = resolver.upstreams[0]

        with patch.object(resolver._quic_pool, "put") as mock_put:
            with pytest.raises(ConnectionError):
                await resolver._forward_quic(query, upstream)
            mock_put.assert_not_called()