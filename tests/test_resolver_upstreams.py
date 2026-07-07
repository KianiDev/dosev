"""
Tests for upstream configuration and resolution logic.
"""

import asyncio
import pytest
import socket
from unittest.mock import AsyncMock, patch, MagicMock

import dns.message
import dns.rdatatype
import dns.rcode

from dosev.resolver import DNSResolver


@pytest.mark.asyncio
async def test_constructor_accepts_upstreams_and_bootstrap():
    upstreams = [{"address": "1.1.1.1", "protocol": "udp", "port": 53}]
    bootstrap = {"servers": ["9.9.9.9:53"], "timeout": 3.0, "retries": 1}
    resolver = DNSResolver(upstreams=upstreams, bootstrap=bootstrap)
    assert resolver.upstreams == upstreams
    assert resolver.bootstrap_servers == ["9.9.9.9:53"]
    assert resolver.bootstrap_timeout == 3.0
    assert resolver.bootstrap_retries == 1


@pytest.mark.asyncio
async def test_default_upstream_when_none_provided():
    resolver = DNSResolver()
    assert len(resolver.upstreams) == 0
    query = dns.message.make_query("example.com", "A").to_wire()
    async def fake_try_upstream(upstream, data):
        return dns.message.make_response(dns.message.from_wire(data)).to_wire()
    resolver._try_upstream = fake_try_upstream
    response = await resolver.forward_dns_query(query)
    assert response is not None


@pytest.mark.asyncio
async def test_resolve_upstream_ip_uses_ip_override():
    resolver = DNSResolver()
    result = await resolver._resolve_upstream_ip("example.com", ip_override="192.0.2.1")
    assert result == "192.0.2.1"

    # invalid -> fallback, but we mock system resolver to avoid real resolution
    with patch.object(resolver, "_udp_query_a_or_aaaa", new=AsyncMock(return_value="203.0.113.1")):
        # Also mock system getaddrinfo to raise so we don't get a real IP
        loop = asyncio.get_running_loop()
        with patch.object(loop, "getaddrinfo", side_effect=socket.gaierror("Mocked")):
            with patch.object(resolver, "_cache_set", new=AsyncMock()):
                result = await resolver._resolve_upstream_ip("example.com", ip_override="invalid")
                assert result == "203.0.113.1"


@pytest.mark.asyncio
async def test_resolve_upstream_ip_uses_bootstrap_when_no_ip():
    resolver = DNSResolver()
    resolver.bootstrap_servers = ["1.1.1.1:53", "8.8.8.8:53"]
    with patch.object(resolver, "_udp_query_a_or_aaaa", new=AsyncMock(return_value="203.0.113.1")):
        with patch.object(resolver, "_cache_set", new=AsyncMock()):
            result = await resolver._resolve_upstream_ip("example.com")
            assert result == "203.0.113.1"


@pytest.mark.asyncio
async def test_forward_udp_uses_ip_override():
    resolver = DNSResolver()
    upstream = {
        "address": "example.com",
        "protocol": "udp",
        "port": 5353,
        "ip": "192.0.2.1"
    }
    data = dns.message.make_query("test.com", "A").to_wire()

    # Mock the datagram endpoint to immediately return a response
    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    fut.set_result(b"dummy_response")

    class DummyTransport:
        def close(self):
            pass

    def fake_create_datagram_endpoint(protocol_factory, remote_addr, **kwargs):
        # protocol_factory() returns a protocol; we need to simulate datagram_received
        proto = protocol_factory()
        # Simulate response after connection
        loop.call_soon(proto.datagram_received, b"dummy_response", ("192.0.2.1", 5353))
        return DummyTransport(), None

    with patch.object(loop, "create_datagram_endpoint", side_effect=fake_create_datagram_endpoint):
        with patch.object(resolver, "_resolve_upstream_ip") as mock_resolve:
            mock_resolve.return_value = "192.0.2.1"
            result = await resolver._forward_udp(data, upstream)
            assert result == b"dummy_response"
            mock_resolve.assert_called_once_with("example.com", ip_override="192.0.2.1")


@pytest.mark.asyncio
async def test_forward_tcp_uses_ip_override():
    resolver = DNSResolver()
    upstream = {
        "address": "example.com",
        "protocol": "tcp",
        "port": 5353,
        "ip": "192.0.2.1"
    }
    data = dns.message.make_query("test.com", "A").to_wire()

    with patch.object(resolver, "_resolve_upstream_ip") as mock_resolve:
        mock_resolve.return_value = "192.0.2.1"
        with patch.object(resolver, "_tcp_pool") as mock_pool:
            mock_pool.get = AsyncMock(return_value=None)
            mock_pool.put = AsyncMock()
            # Mock asyncio.open_connection to return a reader/writer with async drain
            reader = MagicMock()
            writer = MagicMock()
            writer.drain = AsyncMock()
            writer.write = MagicMock()
            writer.is_closing = MagicMock(return_value=False)
            with patch("asyncio.open_connection", new=AsyncMock(return_value=(reader, writer))):
                result = await resolver._forward_tcp(data, upstream)
                # The actual response is read from reader; we need to mock reader.readexactly
                # to avoid reading from network. We'll set reader.readexactly to return dummy.
                # Actually we are mocking the whole open_connection, so we can set up the reader.
                reader.readexactly = AsyncMock(side_effect=[b"\x00\x0d", b"dummy_response"])
                result = await resolver._forward_tcp(data, upstream)
                assert result == b"dummy_response"
                mock_resolve.assert_called_once_with("example.com", ip_override="192.0.2.1")


@pytest.mark.asyncio
async def test_forward_https_uses_ip_override():
    resolver = DNSResolver()
    upstream = {
        "address": "example.com",
        "protocol": "https",
        "port": 443,
        "ip": "192.0.2.1",
        "hostname": "example.com",
        "path": "/dns-query",
        "doh_version": "auto"  # set to auto so it calls _get_auto_doh_version
    }
    data = dns.message.make_query("test.com", "A").to_wire()

    # Mock _get_auto_doh_version to avoid probing and return "1.1"
    with patch.object(resolver, "_get_auto_doh_version", new=AsyncMock(return_value="1.1")):
        # Mock _forward_https1 to avoid HTTP and verify it's called
        with patch.object(resolver, "_forward_https1") as mock_https1:
            mock_https1.return_value = b"dummy_response"
            with patch.object(resolver, "_resolve_upstream_ip") as mock_resolve:
                mock_resolve.return_value = "192.0.2.1"
                result = await resolver._forward_https(data, upstream)
                assert result == b"dummy_response"
                # _resolve_upstream_ip should be called inside _get_auto_doh_version
                mock_resolve.assert_called_once_with("example.com", ip_override="192.0.2.1")


@pytest.mark.asyncio
async def test_forward_quic_uses_ip_override():
    resolver = DNSResolver()
    upstream = {
        "address": "example.com",
        "protocol": "quic",
        "port": 853,
        "ip": "192.0.2.1",
        "hostname": "example.com"
    }
    data = dns.message.make_query("test.com", "A").to_wire()

    with patch.object(resolver, "_resolve_upstream_ip") as mock_resolve:
        mock_resolve.return_value = "192.0.2.1"
        # Mock aioquic's connect to simulate a successful connection and response
        mock_client = MagicMock()
        mock_client._quic = MagicMock()
        mock_client._quic.get_next_available_stream_id = MagicMock(return_value=0)
        mock_client._quic.send_stream_data = MagicMock()
        mock_client.transmit = MagicMock()
        mock_client.response_future = asyncio.Future()
        mock_client.response_future.set_result(b"\x00\x0d" + b"dummy_response")
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("aioquic.asyncio.client.connect", return_value=mock_client):
            # Also need to mock the protocol's wait_connected to not raise
            # We can patch the DoQProtocol.wait_connected method
            with patch("aioquic.asyncio.protocol.QuicConnectionProtocol.wait_connected", new=AsyncMock()):
                result = await resolver._forward_quic(data, upstream)
                assert result == b"dummy_response"
                mock_resolve.assert_called_once_with("example.com", ip_override="192.0.2.1")


@pytest.mark.asyncio
async def test_forward_dns_query_uses_upstreams_list():
    resolver = DNSResolver()
    upstreams = [
        {"address": "1.1.1.1", "protocol": "udp", "port": 53, "ip": "1.1.1.1"},
        {"address": "8.8.8.8", "protocol": "udp", "port": 53, "ip": "8.8.8.8"},
    ]
    resolver.upstreams = upstreams
    query = dns.message.make_query("example.com", "A").to_wire()
    calls = []
    async def fake_try_upstream(upstream, data):
        calls.append(upstream["address"])
        resp = dns.message.make_response(dns.message.from_wire(data))
        return resp.to_wire()
    resolver._try_upstream = fake_try_upstream
    response = await resolver.forward_dns_query(query)
    assert response is not None
    assert calls[0] == "1.1.1.1"


@pytest.mark.asyncio
async def test_forward_dns_query_fallback_default_upstream():
    resolver = DNSResolver(upstreams=[])
    query = dns.message.make_query("example.com", "A").to_wire()
    calls = []
    async def fake_try_upstream(upstream, data):
        calls.append(upstream.get("address", "default"))
        resp = dns.message.make_response(dns.message.from_wire(data))
        return resp.to_wire()
    resolver._try_upstream = fake_try_upstream
    response = await resolver.forward_dns_query(query)
    assert response is not None
    assert len(calls) == 1
    # The default fallback in forward_dns_query is 1.1.1.1
    assert calls[0] == "1.1.1.1"


@pytest.mark.asyncio
async def test_bootstrap_servers_used_for_resolution():
    resolver = DNSResolver()
    resolver.bootstrap_servers = ["1.1.1.1:53", "8.8.8.8:53"]
    mock_udp = AsyncMock(return_value="203.0.113.1")
    with patch.object(resolver, "_udp_query_a_or_aaaa", new=mock_udp):
        with patch.object(resolver, "_cache_set", new=AsyncMock()):
            result = await resolver._resolve_upstream_ip("example.com")
            assert result == "203.0.113.1"
            mock_udp.assert_called()


@pytest.mark.asyncio
async def test_resolve_upstream_ip_falls_back_to_system_resolver():
    resolver = DNSResolver()
    resolver.bootstrap_servers = ["1.1.1.1:53"]
    mock_udp = AsyncMock(return_value=None)
    with patch.object(resolver, "_udp_query_a_or_aaaa", new=mock_udp):
        loop = asyncio.get_running_loop()
        with patch.object(loop, "getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [(None, None, None, None, ("203.0.113.1", 0))]
            with patch.object(resolver, "_cache_set", new=AsyncMock()):
                result = await resolver._resolve_upstream_ip("example.com")
                assert result == "203.0.113.1"
                mock_getaddrinfo.assert_called()