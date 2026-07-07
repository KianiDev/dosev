import asyncio
import dns.message
import dns.rdatatype
import dns.rcode
import pytest
from dosev.resolver import DNSResolver


@pytest.mark.asyncio
async def test_is_blocked_exact_and_suffix():
    resolver = DNSResolver(upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}])
    await resolver.set_blocklist(["example.com", ".bad"])

    assert await resolver.is_blocked("example.com") is True
    assert await resolver.is_blocked("sub.bad") is True
    assert await resolver.is_blocked("good.com") is False


def test_build_block_response_nxdomain():
    resolver = DNSResolver(upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}])
    query = dns.message.make_query("example.com", "A").to_wire()
    response = resolver.build_block_response(query, action="NXDOMAIN")
    msg = dns.message.from_wire(response)
    assert msg.rcode() == dns.rcode.NXDOMAIN


def test_build_nxdomain_response_preserves_opt_section():
    resolver = DNSResolver(upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}])
    query = dns.message.make_query("example.com", "A")
    ecs_opt = dns.edns.ECSOption("192.0.2.0", 24, 0)
    query.use_edns(options=[ecs_opt])
    response = resolver._make_nxdomain_response(query.to_wire())
    msg = dns.message.from_wire(response)

    assert msg.rcode() == dns.rcode.NXDOMAIN
    assert msg.opt is not None
    assert len(msg.options) == 1
    assert isinstance(msg.options[0], dns.edns.ECSOption)
    assert msg.options[0].address == "192.0.2.0"
    assert msg.options[0].srclen == 24


@pytest.mark.asyncio
async def test_forward_preserves_edns_payload(monkeypatch):
    resolver = DNSResolver(upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}])
    query = dns.message.make_query("example.com", "A")
    query.use_edns(payload=8192)
    query_wire = query.to_wire()

    captured = {}
    async def fake_try_upstream(upstream, data):
        captured['wire'] = data
        return dns.message.make_response(dns.message.from_wire(data)).to_wire()

    monkeypatch.setattr(resolver, "_try_upstream", fake_try_upstream)

    response = await resolver.forward_dns_query(query_wire)
    assert captured['wire'] is not None
    sent_msg = dns.message.from_wire(captured['wire'])
    assert sent_msg.opt is not None
    assert sent_msg.payload == 8192
    assert response is not None


@pytest.mark.asyncio
async def test_make_local_a_response_with_hosts_map():
    resolver = DNSResolver(upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}])
    await resolver.set_hosts_map({"example.com": ("203.0.113.1",)})
    query = dns.message.make_query("example.com", "A").to_wire()
    response = await resolver.forward_dns_query(query)
    msg = dns.message.from_wire(response)
    assert len(msg.answer) == 1
    assert msg.answer[0].to_text().endswith("203.0.113.1")


@pytest.mark.asyncio
async def test_forward_dns_query_negative_responses_are_cached(monkeypatch):
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        negative_cache_ttl=5
    )
    query = dns.message.make_query("does-not-exist.example", "A").to_wire()
    calls = 0

    async def fake_try_upstream(upstream, data):
        nonlocal calls
        calls += 1
        req = dns.message.from_wire(data)
        resp = dns.message.make_response(req)
        resp.set_rcode(dns.rcode.NXDOMAIN)
        return resp.to_wire()

    monkeypatch.setattr(resolver, "_try_upstream", fake_try_upstream)

    response1 = await resolver.forward_dns_query(query)
    response2 = await resolver.forward_dns_query(query)

    assert calls == 1
    assert dns.message.from_wire(response1).rcode() == dns.rcode.NXDOMAIN
    assert dns.message.from_wire(response2).rcode() == dns.rcode.NXDOMAIN


@pytest.mark.asyncio
async def test_forward_dns_query_cache_expires(monkeypatch):
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        cache_ttl=1
    )
    query = dns.message.make_query("example.com", "A").to_wire()

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
async def test_forward_dns_query_strips_ecs_when_disabled(monkeypatch):
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        ecs_enabled=False
    )
    query = dns.message.make_query("example.com", "A")
    ecs_opt = dns.edns.ECSOption("192.0.2.0", 24, 0)
    query.use_edns(options=[ecs_opt])
    qwire = query.to_wire()

    called = {}
    async def fake_try_upstream(upstream, data):
        called['data'] = data
        return dns.message.make_response(dns.message.from_wire(data)).to_wire()

    monkeypatch.setattr(resolver, "_try_upstream", fake_try_upstream)

    response = await resolver.forward_dns_query(qwire)
    assert response is not None
    assert 'data' in called
    called_msg = dns.message.from_wire(called['data'])
    assert called_msg.opt is not None
    assert called_msg.options == ()


@pytest.mark.asyncio
async def test_get_auto_doh_version_prefers_http3_then_http2(monkeypatch):
    resolver = DNSResolver(upstreams=[{"address": "1.1.1.1", "protocol": "https", "ip": "1.1.1.1"}], doh_timeout=1.0)

    async def fake_https3(data, hostname, port, host, path, ip_override):
        return b'response'

    async def fake_https2(data, hostname, port, host, path, ip_override):
        return b'response2'

    monkeypatch.setattr(resolver, '_forward_https3', fake_https3)
    monkeypatch.setattr(resolver, '_forward_https2', fake_https2)

    version = await resolver._get_auto_doh_version('example.com', 443, 'example.com', '/dns-query')
    assert version == '3'


@pytest.mark.asyncio
async def test_rate_limiter():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        rate_limit_rps=1.0,
        rate_limit_burst=1.0
    )
    limiter = resolver.rate_limiter
    assert limiter is not None
    assert await limiter.is_allowed("1.2.3.4") is True
    assert await limiter.is_allowed("1.2.3.4") is False
    await asyncio.sleep(1.1)
    assert await limiter.is_allowed("1.2.3.4") is True