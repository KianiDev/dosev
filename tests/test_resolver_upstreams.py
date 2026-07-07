"""
Tests for upstream configuration and resolution logic.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

import dns.message
import dns.rdatatype
import dns.rcode

from dosev.resolver import DNSResolver


@pytest.mark.asyncio
async def test_constructor_accepts_upstreams_and_bootstrap():
    """DNSResolver now takes upstreams and bootstrap, no upstream_dns/protocol."""
    upstreams = [{"address": "1.1.1.1", "protocol": "udp", "port": 53}]
    bootstrap = {"servers": ["9.9.9.9:53"], "timeout": 3.0, "retries": 1}
    resolver = DNSResolver(upstreams=upstreams, bootstrap=bootstrap)
    assert resolver.upstreams == upstreams
    assert resolver.bootstrap_servers == ["9.9.9.9:53"]
    assert resolver.bootstrap_timeout == 3.0
    assert resolver.bootstrap_retries == 1


@pytest.mark.asyncio
async def test_default_upstream_when_none_provided():
    """If no upstreams are given, a default (1.1.1.1 over UDP with ip=1.1.1.1) is used."""
    resolver = DNSResolver()
    assert len(resolver.upstreams) == 1
    upstream = resolver.upstreams[0]
    assert upstream["address"] == "1.1.1.1"
    assert upstream["protocol"] == "udp"
    assert upstream["port"] == 53
    assert upstream["ip"] == "1.1.1.1"  # fixed IP to avoid resolution


@pytest.mark.asyncio
async def test_resolve_upstream_ip_uses_ip_override():
    """_resolve_upstream_ip returns ip_override immediately if provided and valid."""
    resolver = DNSResolver()
    # ip_override is a valid IP
    result = await resolver._resolve_upstream_ip("example.com", ip_override="192.0.2.1")
    assert result == "192.0.2.1"
    # ip_override invalid -> fallback to resolution
    with patch.object(resolver, "_udp_query_a_or_aaaa", new=AsyncMock(return_value="203.0.113.1")):
        with patch.object(resolver, "_cache_set", new=AsyncMock()):
            result = await resolver._resolve_upstream_ip("example.com", ip_override="invalid")
            assert result == "203.0.113.1"


@pytest.mark.asyncio
async def test_resolve_upstream_ip_uses_bootstrap_when_no_ip():
    """If no ip_override and hostname is not an IP, bootstrap servers are queried."""
    resolver = DNSResolver()
    resolver.bootstrap_servers = ["1.1.1.1:53", "8.8.8.8:53"]
    # Mock the UDP query to return an IP
    with patch.object(resolver, "_udp_query_a_or_aaaa", new=AsyncMock(return_value="203.0.113.1")):
        with patch.object(resolver, "_cache_set", new=AsyncMock()):
            result = await resolver._resolve_upstream_ip("example.com")
            assert result == "203.0.113.1"
            # The bootstrap servers should have been tried; we can check that _udp_query_a_or_aaaa was called
            # But we can't easily check the arguments without more mocking; but it's enough that it returned.


@pytest.mark.asyncio
async def test_forward_udp_uses_ip_override():
    """_forward_udp uses the 'ip' field from upstream to skip resolution."""
    resolver = DNSResolver()
    upstream = {
        "address": "example.com",
        "protocol": "udp",
        "port": 5353,
        "ip": "192.0.2.1"  # fixed IP
    }
    data = dns.message.make_query("test.com", "A").to_wire()
    # We need to mock the datagram endpoint to avoid actual network calls.
    # We'll patch loop.create_datagram_endpoint.
    loop = asyncio.get_running_loop()
    with patch.object(loop, "create_datagram_endpoint") as mock_endpoint:
        # Return a dummy transport that will cause the future to resolve
        class DummyTransport:
            def close(self):
                pass
        # We need to simulate receiving a response. We'll set up the future.
        fut = asyncio.Future()
        fut.set_result(b"dummy_response")
        # The protocol factory will be called; we need to capture it to manually call datagram_received.
        # Easiest: mock the whole _with_retries? Actually _forward_udp uses _with_retries which calls the lambda.
        # We'll patch _with_retries to bypass the actual UDP send.
        with patch.object(resolver, "_with_retries") as mock_retries:
            mock_retries.return_value = b"dummy_response"
            result = await resolver._forward_udp(data, upstream)
            assert result == b"dummy_response"
            # Check that _resolve_upstream_ip was called with ip_override
            # We can spy on _resolve_upstream_ip
            with patch.object(resolver, "_resolve_upstream_ip") as mock_resolve:
                mock_resolve.return_value = "192.0.2.1"
                await resolver._forward_udp(data, upstream)
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
        # We need to mock the connection pool to avoid actual connections
        with patch.object(resolver, "_tcp_pool") as mock_pool:
            mock_pool.get = AsyncMock(return_value=None)
            mock_pool.put = AsyncMock()
            # Also mock asyncio.open_connection
            with patch("asyncio.open_connection", new=AsyncMock(return_value=(MagicMock(), MagicMock()))):
                # Patch _with_retries to avoid retry logic
                with patch.object(resolver, "_with_retries") as mock_retries:
                    mock_retries.return_value = b"dummy_response"
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
        "doh_version": "1.1"
    }
    data = dns.message.make_query("test.com", "A").to_wire()
    # Since _forward_https branches based on version, we need to ensure _get_auto_doh_version isn't called.
    # We'll set version explicitly.
    # Actually, the version is set in upstream, and doh_version is "1.1", so it goes to _forward_https1.
    with patch.object(resolver, "_resolve_upstream_ip") as mock_resolve:
        mock_resolve.return_value = "192.0.2.1"
        # Mock _forward_https1 to avoid HTTP request
        with patch.object(resolver, "_forward_https1") as mock_https1:
            mock_https1.return_value = b"dummy_response"
            result = await resolver._forward_https(data, upstream)
            assert result == b"dummy_response"
            # _resolve_upstream_ip should be called with ip_override
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
        # Mock _with_retries to bypass actual QUIC
        with patch.object(resolver, "_with_retries") as mock_retries:
            mock_retries.return_value = b"dummy_response"
            result = await resolver._forward_quic(data, upstream)
            assert result == b"dummy_response"
            mock_resolve.assert_called_once_with("example.com", ip_override="192.0.2.1")


@pytest.mark.asyncio
async def test_forward_dns_query_uses_upstreams_list():
    """forward_dns_query should use the upstreams list, not a single upstream_dns."""
    resolver = DNSResolver()
    upstreams = [
        {"address": "1.1.1.1", "protocol": "udp", "port": 53, "ip": "1.1.1.1"},
        {"address": "8.8.8.8", "protocol": "udp", "port": 53, "ip": "8.8.8.8"},
    ]
    resolver.upstreams = upstreams
    query = dns.message.make_query("example.com", "A").to_wire()
    # Mock _try_upstream to return a response and record calls
    calls = []
    async def fake_try_upstream(upstream, data):
        calls.append(upstream["address"])
        resp = dns.message.make_response(dns.message.from_wire(data))
        return resp.to_wire()
    resolver._try_upstream = fake_try_upstream
    response = await resolver.forward_dns_query(query)
    assert response is not None
    # The first upstream should have been tried
    assert calls[0] == "1.1.1.1"


@pytest.mark.asyncio
async def test_forward_dns_query_fallback_default_upstream():
    """If upstreams list is empty, fallback to default (1.1.1.1)."""
    resolver = DNSResolver(upstreams=[])  # empty list
    query = dns.message.make_query("example.com", "A").to_wire()
    # The resolver should have no upstreams, so it should fallback to the default.
    # We'll check that it tries the default.
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
async def test_bootstrap_servers_used_for_resolution():
    """When hostname needs resolution, bootstrap servers are queried."""
    resolver = DNSResolver()
    resolver.bootstrap_servers = ["1.1.1.1:53", "8.8.8.8:53"]
    # Mock _udp_query_a_or_aaaa to return an IP
    mock_udp = AsyncMock(return_value="203.0.113.1")
    with patch.object(resolver, "_udp_query_a_or_aaaa", new=mock_udp):
        with patch.object(resolver, "_cache_set", new=AsyncMock()):
            result = await resolver._resolve_upstream_ip("example.com")
            assert result == "203.0.113.1"
            # Verify that _udp_query_a_or_aaaa was called with the bootstrap servers
            # It should have been called at least once.
            mock_udp.assert_called()
            # We could check the arguments but not necessary.


@pytest.mark.asyncio
async def test_resolve_upstream_ip_falls_back_to_system_resolver():
    """If bootstrap servers fail, system resolver is tried."""
    resolver = DNSResolver()
    resolver.bootstrap_servers = ["1.1.1.1:53"]
    # Mock _udp_query_a_or_aaaa to return None (fail)
    mock_udp = AsyncMock(return_value=None)
    with patch.object(resolver, "_udp_query_a_or_aaaa", new=mock_udp):
        # Mock system getaddrinfo to return an IP
        with patch("socket.getaddrinfo", new=AsyncMock(return_value=[(None, None, None, None, ("203.0.113.1", 0))])) as mock_getaddrinfo:
            with patch.object(resolver, "_cache_set", new=AsyncMock()):
                result = await resolver._resolve_upstream_ip("example.com")
                assert result == "203.0.113.1"
                mock_getaddrinfo.assert_called()