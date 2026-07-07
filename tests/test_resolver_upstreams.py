import asyncio
import pytest
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
    # Now we rely on the default upstream built into the resolver.
    # Actually, the resolver doesn't add a default; the config does.
    # In resolver, if upstreams is empty, it will fallback in forward_dns_query.
    # So we test that forward_dns_query works with empty upstreams.
    assert len(resolver.upstreams) == 0
    query = dns.message.make_query("example.com", "A").to_wire()
    # Mock _try_upstream to avoid network
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
    # invalid -> fallback, but we mock udp query
    with patch.object(resolver, "_udp_query_a_or_aaaa", new=AsyncMock(return_value="203.0.113.1")):
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
    # We'll mock the _with_retries to avoid actual UDP
    with patch.object(resolver, "_with_retries") as mock_retries:
        mock_retries.return_value = b"dummy_response"
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
    with patch.object(resolver, "_with_retries") as mock_retries:
        mock_retries.return_value = b"dummy_response"
        with patch.object(resolver, "_resolve_upstream_ip") as mock_resolve:
            mock_resolve.return_value = "192.0.2.1"
            # Mock connection pool and open_connection
            with patch.object(resolver, "_tcp_pool") as mock_pool:
                mock_pool.get = AsyncMock(return_value=None)
                mock_pool.put = AsyncMock()
                with patch("asyncio.open_connection", new=AsyncMock(return_value=(MagicMock(), MagicMock()))):
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
    with patch.object(resolver, "_forward_https1") as mock_https1:
        mock_https1.return_value = b"dummy_response"
        with patch.object(resolver, "_resolve_upstream_ip") as mock_resolve:
            mock_resolve.return_value = "192.0.2.1"
            result = await resolver._forward_https(data, upstream)
            assert result == b"dummy_response"
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
    with patch.object(resolver, "_with_retries") as mock_retries:
        mock_retries.return_value = b"dummy_response"
        with patch.object(resolver, "_resolve_upstream_ip") as mock_resolve:
            mock_resolve.return_value = "192.0.2.1"
            # Mock aioquic connect to avoid real connection
            with patch("aioquic.asyncio.client.connect") as mock_connect:
                mock_connect.return_value.__aenter__.return_value = MagicMock()
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
    # The fallback default upstream (hardcoded in forward_dns_query) should be used.
    # In forward_dns_query, if upstream_list is empty, it uses a default.
    # We can't easily check the address, but we can ensure it didn't raise.
    assert len(calls) == 1
    # The default is 1.1.1.1
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
        # We need to mock getaddrinfo properly. It's a blocking call in asyncio.
        # We'll mock asyncio.get_running_loop().getaddrinfo
        loop = asyncio.get_running_loop()
        with patch.object(loop, "getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [(None, None, None, None, ("203.0.113.1", 0))]
            with patch.object(resolver, "_cache_set", new=AsyncMock()):
                result = await resolver._resolve_upstream_ip("example.com")
                assert result == "203.0.113.1"
                mock_getaddrinfo.assert_called()