"""
Tests for DoQ (DNS over QUIC) connection pooling.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

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

    async def wait_connected(self):
        if not self._connected:
            raise ConnectionError("Connection failed")
        return True


@pytest.fixture
def resolver():
    return DNSResolver(upstreams=[{"address": "example.com", "protocol": "quic", "port": 853}])


@pytest.fixture
def mock_connect():
    """Mock aioquic.asyncio.client.connect"""
    with patch("aioquic.asyncio.client.connect") as mock:
        yield mock


@pytest.mark.asyncio
async def test_doq_connection_pool_reuse(resolver, mock_connect):
    """Verify that DoQ connections are reused from the pool."""
    # Create a mock client that is not closed
    mock_client = MockQuicClient(closed=False)
    mock_connect.return_value = mock_client

    # We'll also need to patch asyncio.wait_for to immediately return a response
    dummy_response = b"\x00\x0d" + b"dummy_response"
    with patch("asyncio.wait_for", new=AsyncMock(return_value=dummy_response)):
        query = dns.message.make_query("example.com", "A").to_wire()
        upstream = resolver.upstreams[0]

        # First query should create a new connection
        result1 = await resolver._forward_quic(query, upstream)
        assert result1 == b"dummy_response"
        assert mock_connect.call_count == 1

        # Second query should reuse the connection from the pool
        result2 = await resolver._forward_quic(query, upstream)
        assert result2 == b"dummy_response"
        # connect should still be called only once
        assert mock_connect.call_count == 1

        # Verify that the pool put was called (connection was returned)
        # We can check that the client was put back: the pool is an attribute of resolver
        # We'll patch the pool's put method to track calls
        with patch.object(resolver._quic_pool, "put") as mock_put:
            await resolver._forward_quic(query, upstream)
            # Should be called with the key and the client
            mock_put.assert_called_once()


@pytest.mark.asyncio
async def test_doq_connection_pool_closed_connection(resolver, mock_connect):
    """If a pooled connection is closed, a new one should be created."""
    # First query: connection is open
    mock_client_open = MockQuicClient(closed=False)
    # Second query: the same client will be returned from the pool but closed
    mock_client_closed = MockQuicClient(closed=True)
    # We'll simulate get returning the closed client, so we need to patch the pool get
    # to return the closed client on the second call.
    # But more directly: we can patch resolver._quic_pool.get to return the closed client.
    # We'll make a list of clients to return in sequence.
    clients = [mock_client_open, mock_client_closed]
    mock_connect.side_effect = clients

    dummy_response = b"\x00\x0d" + b"dummy_response"
    with patch("asyncio.wait_for", new=AsyncMock(return_value=dummy_response)):
        # First query: should create a new connection
        upstream = resolver.upstreams[0]
        query = dns.message.make_query("example.com", "A").to_wire()

        # We'll also need to patch the pool.get to return the closed client on second call
        # But we can test the logic inside _forward_quic: it calls pool.get, checks if client._quic.closed
        # We'll mock pool.get to return the closed client
        with patch.object(resolver._quic_pool, "get") as mock_pool_get:
            # First call returns None (no pooled connection)
            # Second call returns the closed client
            mock_pool_get.side_effect = [None, mock_client_closed]

            # First query: should create a new connection
            result1 = await resolver._forward_quic(query, upstream)
            assert result1 == b"dummy_response"
            assert mock_connect.call_count == 1  # connect called for the first client

            # Second query: pool.get returns closed client; should discard and create new
            result2 = await resolver._forward_quic(query, upstream)
            assert result2 == b"dummy_response"
            assert mock_connect.call_count == 2  # connect called again

            # Verify that the closed client was not put back (we can check put was called only once)
            with patch.object(resolver._quic_pool, "put") as mock_put:
                # Now we need to reset mock_connect call count for clarity; we already have 2 calls.
                # We'll run a third query to see that the new open client is put back.
                # But we need to set up mock_pool_get to return None (no pooled client) after the second query?
                # Actually the third query will again call pool.get, which we have side_effect set to return the closed client again.
                # That would cause a new connection each time. We'll instead test the put logic by directly observing.
                # We'll test that when a connection is open and not closed, it's put back.

                # Reset mocks
                mock_connect.reset_mock()
                mock_connect.return_value = MockQuicClient(closed=False)

                # Clear the pool get side effect to return None (simulate no pooled client)
                mock_pool_get.side_effect = None
                mock_pool_get.return_value = None

                # Now do a fresh query; it should create a new connection and then put it back
                result3 = await resolver._forward_quic(query, upstream)
                assert result3 == b"dummy_response"
                assert mock_connect.call_count == 1
                mock_put.assert_called_once()


@pytest.mark.asyncio
async def test_doq_connection_pool_handles_timeout(resolver, mock_connect):
    """If a DoQ query times out, the connection should not be put back into the pool."""
    mock_client = MockQuicClient(closed=False)
    mock_connect.return_value = mock_client

    # Simulate a timeout by making asyncio.wait_for raise TimeoutError
    with patch("asyncio.wait_for", new=AsyncMock(side_effect=asyncio.TimeoutError)):
        query = dns.message.make_query("example.com", "A").to_wire()
        upstream = resolver.upstreams[0]

        # The _forward_quic should raise TimeoutError
        with pytest.raises(TimeoutError):
            await resolver._forward_quic(query, upstream)

        # The client should NOT be put back into the pool
        with patch.object(resolver._quic_pool, "put") as mock_put:
            # We need to ensure the client is not put back even if the exception is handled.
            # Actually, the current code in _forward_quic has a try/finally that attempts to pop the future,
            # and then after parsing the response it puts the client back. But if TimeoutError is raised,
            # the code will go to the except block, and then the finally block will remove the future.
            # However, the client is put back *after* the try/except block? No, in the original code,
            # the client is put back at the end of the function, after the try/except. So if an exception is raised,
            # the function exits and the client is not put back.
            # So we need to verify that the put method is NOT called.
            # We'll patch the put and check it's not called.
            mock_put.reset_mock()
            try:
                await resolver._forward_quic(query, upstream)
            except TimeoutError:
                pass
            mock_put.assert_not_called()


@pytest.mark.asyncio
async def test_doq_pool_handles_connection_error_during_handshake(resolver, mock_connect):
    """If the QUIC handshake fails (wait_connected raises), the connection should not be pooled."""
    # Create a client that fails to connect
    mock_client = MockQuicClient()
    mock_client._connected = False  # wait_connected will raise ConnectionError
    mock_connect.return_value = mock_client

    query = dns.message.make_query("example.com", "A").to_wire()
    upstream = resolver.upstreams[0]

    with patch.object(resolver._quic_pool, "put") as mock_put:
        # The call should raise ConnectionError
        with pytest.raises(ConnectionError):
            await resolver._forward_quic(query, upstream)

        # The client should not be put back (it failed to connect)
        mock_put.assert_not_called()