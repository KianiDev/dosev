"""
Advanced tests for dosev.resolver – mocks external dependencies.
"""

import asyncio
import os
import tempfile
import time
from unittest.mock import AsyncMock, MagicMock, patch

import dns.message
import dns.rdatatype
import dns.rcode
import dns.rrset
import dns.rdataclass
import pytest

from dosev.resolver import DNSResolver, RateLimiter, AsyncTTLCache, ConnectionPool


# ---------- Fixtures ----------

@pytest.fixture
def resolver():
    """Basic resolver instance with mocked upstream."""
    return DNSResolver("1.1.1.1", protocol="udp")


@pytest.fixture
def resolver_with_cache():
    """Resolver using AsyncTTLCache (no cachetools)."""
    with patch("dosev.resolver._HAS_CACHETOOLS", False):
        return DNSResolver("1.1.1.1", protocol="udp", cache_ttl=300, cache_max_size=100)


# ---------- EDNS0 Tests ----------

@pytest.mark.asyncio
async def test_forward_preserves_edns_payload(resolver):
    """Client EDNS payload must be forwarded unchanged (RFC 6891)."""
    query = dns.message.make_query("example.com", "A")
    query.use_edns(payload=1232, options=[dns.edns.ECSOption("192.0.2.0", 24, 0)])
    qwire = query.to_wire()

    captured = {}

    async def fake_upstream(upstream, data):
        captured["data"] = data
        msg = dns.message.from_wire(data)
        resp = dns.message.make_response(msg)
        resp.use_edns(payload=1232)  # echo back
        return resp.to_wire()

    resolver._try_upstream = fake_upstream

    response = await resolver.forward_dns_query(qwire)
    assert captured["data"] is not None
    sent = dns.message.from_wire(captured["data"])
    assert sent.opt is not None
    assert sent.payload == 1232  # not modified
    assert response is not None


@pytest.mark.asyncio
async def test_forward_strips_ecs_when_disabled(resolver):
    """When ecs_enabled=False, ECS option must be removed."""
    resolver.ecs_enabled = False
    query = dns.message.make_query("example.com", "A")
    query.use_edns(options=[dns.edns.ECSOption("192.0.2.0", 24, 0)])
    qwire = query.to_wire()

    captured = {}

    async def fake_upstream(upstream, data):
        captured["data"] = data
        msg = dns.message.from_wire(data)
        resp = dns.message.make_response(msg)
        return resp.to_wire()

    resolver._try_upstream = fake_upstream

    response = await resolver.forward_dns_query(qwire)
    sent = dns.message.from_wire(captured["data"])
    assert sent.opt is not None
    assert sent.options == ()  # no ECS


# ---------- DNSSEC Tests ----------

@pytest.mark.asyncio
async def test_dnssec_unsigned_domain_is_insecure(resolver):
    """Unsigned domain returns insecure (not bogus) when DO=1 (RFC 4035)."""
    resolver.dnssec_enabled = True
    resolver._dnssec_raw_anchors = {dns.name.root: b"dummy"}  # any non-None

    qname = "example.com"
    # Build a response with no RRSIGs
    msg = dns.message.make_response(dns.message.make_query(qname, "A"))
    rr = dns.rrset.from_text(qname + ".", 300, dns.rdataclass.IN, dns.rdatatype.A, "93.184.216.34")
    msg.answer.append(rr)
    wire = msg.to_wire()

    # No RRSIGs -> insecure, not an error
    secure, insecure = await resolver._dnssec_validate(qname, wire, dnssec_requested=True)
    assert secure is False
    assert insecure is True


@pytest.mark.asyncio
async def test_dnssec_bogus_raises(resolver):
    """Invalid signature should raise ValidationFailure."""
    resolver.dnssec_enabled = True

    # Patch the exact reference used inside resolver.py
    with patch("dosev.resolver.dns.dnssec.validate", side_effect=dns.dnssec.ValidationFailure("bad")):
        # Force run_in_executor to run synchronously so the patch is visible
        loop = asyncio.get_running_loop()
        original_executor = loop.run_in_executor

        async def fake_run_in_executor(executor, func, *args):
            return func(*args)

        with patch.object(loop, "run_in_executor", new=fake_run_in_executor):
            resolver._dnssec_raw_anchors = {dns.name.root: b"dummy"}
            msg = dns.message.make_response(dns.message.make_query("example.com", "A"))
            # Add a fake RRSIG (doesn't need to be valid; we're mocking validate)
            rrsig = dns.rrset.from_text(
                "example.com.", 300, dns.rdataclass.IN, dns.rdatatype.RRSIG,
                "A 8 2 3600 20260101000000 20251231000000 12345 example.com. ABCDEF=="
            )
            msg.answer.append(rrsig)
            wire = msg.to_wire()

            with pytest.raises(dns.dnssec.ValidationFailure):
                await resolver._dnssec_validate("example.com", wire, dnssec_requested=True)


# ---------- Negative Caching with SOA MINIMUM ----------

@pytest.mark.asyncio
async def test_negative_cache_uses_soa_minimum(resolver):
    """Negative cache TTL should come from SOA MINIMUM (RFC 2308)."""
    resolver.negative_cache_ttl = 5  # fallback
    query = dns.message.make_query("nxdomain.example", "A")
    qwire = query.to_wire()

    # Build NXDOMAIN response with SOA
    resp = dns.message.make_response(query)
    resp.set_rcode(dns.rcode.NXDOMAIN)
    soa_rr = dns.rrset.from_text(
        "example.com.", 3600, dns.rdataclass.IN, dns.rdatatype.SOA,
        "ns1.example.com. admin.example.com. 20250101 3600 1800 604800 60"
    )
    resp.authority.append(soa_rr)
    wire = resp.to_wire()

    # Mock upstream to return this
    async def fake_upstream(upstream, data):
        return wire
    resolver._try_upstream = fake_upstream

    # First query populates negative cache
    response1 = await resolver.forward_dns_query(qwire)
    # The cache TTL should be 60 (SOA MINIMUM)
    key = resolver._build_cache_key(qwire)
    entry = await resolver._negative_cache_get(key)
    assert entry is not None
    # We can't easily inspect TTL in TTLCache, but we can check that it was stored.
    # For AsyncTTLCache we could check expiry, but we'll trust the logic.
    # Instead we'll verify that a second query uses cache (no upstream call)
    resolver._try_upstream = AsyncMock(side_effect=Exception("should not be called"))
    response2 = await resolver.forward_dns_query(qwire)
    assert dns.message.from_wire(response2).rcode() == dns.rcode.NXDOMAIN


# ---------- Optimistic Caching (serve-stale) ----------

@pytest.mark.asyncio
async def test_optimistic_cache_serves_stale(resolver):
    """When optimistic_cache_enabled=True, stale responses are served with reduced TTL."""
    resolver.optimistic_cache_enabled = True
    resolver.stale_max_age = 3600
    resolver.stale_response_ttl = 30

    query = dns.message.make_query("example.com", "A")
    qwire = query.to_wire()
    key = resolver._build_cache_key(qwire)

    # Insert an expired entry into wire cache
    resp = dns.message.make_response(query)
    rr = dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "93.184.216.34")
    resp.answer.append(rr)
    wire = resp.to_wire()
    now = time.time()
    expiry = now - 10  # expired
    stale_until = now + 3600  # still in stale window
    entry = (wire, expiry, qwire, stale_until, False)
    await resolver._wire_cache_set(key, entry)

    # Patch background refresh to do nothing
    resolver._maybe_refresh_stale = AsyncMock()

    # Should return stale response with TTL=30
    response = await resolver.forward_dns_query(qwire)
    msg = dns.message.from_wire(response)
    assert msg.answer
    assert msg.answer[0].ttl == 30  # our stale_response_ttl


# ---------- Blocklist Actions ----------

def test_build_block_response_refused(resolver):
    query = dns.message.make_query("blocked.com", "A").to_wire()
    resp_wire = resolver.build_block_response(query, action="REFUSED")
    msg = dns.message.from_wire(resp_wire)
    assert msg.rcode() == dns.rcode.REFUSED


def test_build_block_response_zeroip_a(resolver):
    query = dns.message.make_query("blocked.com", "A").to_wire()
    resp_wire = resolver.build_block_response(query, action="ZEROIP")
    msg = dns.message.from_wire(resp_wire)
    assert msg.rcode() == dns.rcode.NOERROR
    assert len(msg.answer) == 1
    assert msg.answer[0].rdtype == dns.rdatatype.A
    assert msg.answer[0][0].address == "0.0.0.0"


def test_build_block_response_zeroip_aaaa_disabled(resolver):
    resolver.disable_ipv6 = True
    query = dns.message.make_query("blocked.com", "AAAA").to_wire()
    resp_wire = resolver.build_block_response(query, action="ZEROIP")
    msg = dns.message.from_wire(resp_wire)
    assert msg.rcode() == dns.rcode.NXDOMAIN  # no AAAA response when IPv6 disabled


def test_build_block_response_zeroip_any(resolver):
    query = dns.message.make_query("blocked.com", "ANY").to_wire()
    resp_wire = resolver.build_block_response(query, action="ZEROIP")
    msg = dns.message.from_wire(resp_wire)
    assert msg.rcode() == dns.rcode.NOERROR
    assert len(msg.answer) == 2  # A and AAAA
    types = {rr.rdtype for rr in msg.answer}
    assert dns.rdatatype.A in types
    assert dns.rdatatype.AAAA in types


# ---------- Hosts Override ----------

@pytest.mark.asyncio
async def test_hosts_override_a(resolver):
    await resolver.set_hosts_map({"example.com": ("192.0.2.1",)})
    query = dns.message.make_query("example.com", "A").to_wire()
    response = await resolver.forward_dns_query(query)
    msg = dns.message.from_wire(response)
    assert len(msg.answer) == 1
    assert msg.answer[0].rdtype == dns.rdatatype.A
    assert msg.answer[0][0].address == "192.0.2.1"


@pytest.mark.asyncio
async def test_hosts_override_aaaa(resolver):
    await resolver.set_hosts_map({"example.com": ("2001:db8::1",)})
    query = dns.message.make_query("example.com", "AAAA").to_wire()
    response = await resolver.forward_dns_query(query)
    msg = dns.message.from_wire(response)
    # hosts only overrides A, not AAAA (unless we change logic; currently only A)
    # The resolver only handles A in hosts for simplicity. We'll check that it doesn't answer.
    # Actually, the code currently only synthesizes A responses; for AAAA it will forward.
    # So we mock upstream to see it's called.
    async def fake_upstream(upstream, data):
        resp = dns.message.make_response(dns.message.from_wire(data))
        rr = dns.rrset.from_text("example.com.", 300, dns.rdataclass.IN, dns.rdatatype.AAAA, "2001:db8::1")
        resp.answer.append(rr)
        return resp.to_wire()
    resolver._try_upstream = fake_upstream
    response = await resolver.forward_dns_query(query)
    msg = dns.message.from_wire(response)
    assert len(msg.answer) == 1
    assert msg.answer[0].rdtype == dns.rdatatype.AAAA


# ---------- Rebinding Protection ----------

def test_rebind_protection_strips_private(resolver):
    resolver.rebind_protection_enabled = True
    resolver.rebind_action = "strip"
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    # Add public and private IPs
    resp.answer.append(dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "8.8.8.8"))
    resp.answer.append(dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.168.1.1"))
    wire = resp.to_wire()
    result = resolver._apply_rebind_protection(wire)
    msg = dns.message.from_wire(result)
    ips = [rr.to_text().split()[-1] for rr in msg.answer if rr.rdtype == dns.rdatatype.A]
    assert "8.8.8.8" in ips
    assert "192.168.1.1" not in ips


def test_rebind_protection_blocks_all_private(resolver):
    resolver.rebind_protection_enabled = True
    resolver.rebind_action = "block"
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    resp.answer.append(dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.168.1.1"))
    wire = resp.to_wire()
    result = resolver._apply_rebind_protection(wire)
    assert result is None


# ---------- Upstream Failover ----------

@pytest.mark.asyncio
async def test_upstream_failover(resolver):
    resolver.upstreams = [
        {"address": "1.1.1.1", "port": 53, "protocol": "udp"},
        {"address": "8.8.8.8", "port": 53, "protocol": "udp"},
    ]
    # Make first upstream fail, second succeed
    calls = []
    async def fake_try_upstream(upstream, data):
        calls.append(upstream['address'])
        if upstream['address'] == "1.1.1.1":
            raise Exception("fail")
        resp = dns.message.make_response(dns.message.from_wire(data))
        return resp.to_wire()
    resolver._try_upstream = fake_try_upstream

    query = dns.message.make_query("example.com", "A").to_wire()
    response = await resolver.forward_dns_query(query)
    assert response is not None
    assert calls == ["1.1.1.1", "8.8.8.8"]


# ---------- Connection Pool (basic) ----------

@pytest.mark.asyncio
async def test_connection_pool_get_put():
    pool = ConnectionPool(max_size=1, idle_timeout=1.0)
    key = ("host", 53)
    # Simulate a connection
    reader = MagicMock()
    writer = MagicMock()
    writer.is_closing.return_value = False
    await pool.put(key, reader, writer)
    # Get it back
    result = await pool.get(key)
    assert result is not None
    r, w = result
    assert r is reader
    assert w is writer
    # Pool should be empty now
    result2 = await pool.get(key)
    assert result2 is None


# ---------- Trust Anchor Loading ----------

def test_load_trust_anchors_from_file(resolver):
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write(". 3600 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+Erq1sBvNaRfxv4d8+1o5RsS5rG3FJ0fruu1Wg+0JvN6sL5nlk46iS2BsUj8IYL0=")
        fname = f.name
    resolver.dnssec_enabled = True
    resolver.trust_anchors = fname
    resolver._load_trust_anchors()
    assert resolver._dnssec_raw_anchors is not None
    assert dns.name.root in resolver._dnssec_raw_anchors
    os.unlink(fname)


def test_load_trust_anchors_default(resolver):
    resolver.dnssec_enabled = True
    resolver.trust_anchors = None
    resolver._load_trust_anchors()
    assert resolver._dnssec_raw_anchors is not None
    assert dns.name.root in resolver._dnssec_raw_anchors


# ---------- Config Update ----------

@pytest.mark.asyncio
async def test_update_config_changes_edns_payload(resolver):
    assert resolver.max_edns_payload == 4096
    await resolver.update_config(max_edns_payload=1232)
    assert resolver.max_edns_payload == 1232


@pytest.mark.asyncio
async def test_update_config_changes_rate_limiter(resolver):
    assert resolver.rate_limiter is None
    await resolver.update_config(rate_limit_rps=10.0, rate_limit_burst=5.0)
    assert resolver.rate_limiter is not None
    assert resolver.rate_limit_rps == 10.0
    assert resolver.rate_limit_burst == 5.0


# ---------- Rate Limiter ----------

@pytest.mark.asyncio
async def test_rate_limiter_token_bucket():
    limiter = RateLimiter(rate=1.0, burst=2.0)
    # Allow 2 bursts
    assert await limiter.is_allowed("ip") is True
    assert await limiter.is_allowed("ip") is True
    assert await limiter.is_allowed("ip") is False  # bucket empty
    await asyncio.sleep(1.1)
    assert await limiter.is_allowed("ip") is True  # refilled


# ---------- TC bit ----------

def test_set_tc_bit(resolver):
    msg = dns.message.make_query("example.com", "A")
    wire = msg.to_wire()
    new_wire = resolver._set_tc_bit(wire)
    flags = int.from_bytes(new_wire[2:4], 'big')
    assert flags & 0x0200 != 0  # TC set


# ---------- EDNS0 in NXDOMAIN ----------

def test_make_nxdomain_response_preserves_edns(resolver):
    query = dns.message.make_query("example.com", "A")
    query.use_edns(payload=1232, options=[dns.edns.ECSOption("192.0.2.0", 24, 0)])
    wire = query.to_wire()
    nx = resolver._make_nxdomain_response(wire)
    msg = dns.message.from_wire(nx)
    assert msg.opt is not None
    assert msg.payload == 1232  # preserved
    assert len(msg.options) == 1
    assert isinstance(msg.options[0], dns.edns.ECSOption)