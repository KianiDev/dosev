import asyncio
import dns.message
import dns.rdatatype
import dns.rcode
import pytest
from dosev.resolver import DNSResolver


@pytest.mark.asyncio
async def test_is_blocked_exact_and_suffix():
    resolver = DNSResolver("1.1.1.1", protocol="udp")
    await resolver.set_blocklist(["example.com", ".bad"])

    assert await resolver.is_blocked("example.com") is True
    assert await resolver.is_blocked("sub.bad") is True
    assert await resolver.is_blocked("good.com") is False


def test_build_block_response_nxdomain():
    resolver = DNSResolver("1.1.1.1", protocol="udp")
    query = dns.message.make_query("example.com", "A").to_wire()
    response = resolver.build_block_response(query, action="NXDOMAIN")
    msg = dns.message.from_wire(response)
    assert msg.rcode() == dns.rcode.NXDOMAIN


@pytest.mark.asyncio
async def test_make_local_a_response_with_hosts_map():
    resolver = DNSResolver("1.1.1.1", protocol="udp")
    await resolver.set_hosts_map({"example.com": ("203.0.113.1",)})
    query = dns.message.make_query("example.com", "A").to_wire()
    response = await resolver.forward_dns_query(query)
    msg = dns.message.from_wire(response)
    assert len(msg.answer) == 1
    assert msg.answer[0].to_text().endswith("203.0.113.1")


@pytest.mark.asyncio
async def test_forward_dns_query_cache_expires(monkeypatch):
    resolver = DNSResolver("1.1.1.1", protocol="udp", cache_ttl=1)
    query = dns.message.make_query("example.com", "A").to_wire()

    # Plain function – no 'self' because it's assigned to instance (not bound)
    async def fake_try_upstream(upstream, data):
        return dns.message.make_response(dns.message.from_wire(data)).to_wire()

    monkeypatch.setattr(resolver, "_try_upstream", fake_try_upstream)

    response1 = await resolver.forward_dns_query(query)
    response2 = await resolver.forward_dns_query(query)
    assert response1 == response2

    await asyncio.sleep(1.1)
    response3 = await resolver.forward_dns_query(query)
    assert response3 == response1


@pytest.mark.asyncio
async def test_get_auto_doh_version_prefers_http3_then_http2(monkeypatch):
    resolver = DNSResolver("1.1.1.1", protocol="https", doh_timeout=1.0)

    # These are plain functions assigned to instance – they won't receive 'self'
    async def fake_https3(data, hostname, port, host, path):
        return b'response'

    async def fake_https2(data, hostname, port, host, path):
        return b'response2'  # Not reached

    monkeypatch.setattr(resolver, '_forward_https3', fake_https3)
    monkeypatch.setattr(resolver, '_forward_https2', fake_https2)

    version = await resolver._get_auto_doh_version('example.com', 443, 'example.com', '/dns-query')
    assert version == '3'


@pytest.mark.asyncio
async def test_rate_limiter():
    resolver = DNSResolver("1.1.1.1", protocol="udp", rate_limit_rps=1.0, rate_limit_burst=1.0)
    limiter = resolver.rate_limiter
    assert limiter is not None
    assert await limiter.is_allowed("1.2.3.4") is True
    assert await limiter.is_allowed("1.2.3.4") is False
    await asyncio.sleep(1.1)
    assert await limiter.is_allowed("1.2.3.4") is True