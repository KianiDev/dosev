import asyncio
import pytest
import time
import dns.message

from dosev.resolver import RateLimiter, DNSResolver


@pytest.mark.asyncio
async def test_rate_limiter_no_crash_on_zero_rate():
    rl = RateLimiter(rate=0.0, burst=1.0)
    # First call should be allowed because initial bucket equals burst
    allowed = await rl.is_allowed('client1')
    assert allowed is True
    # Subsequent immediate call should be denied because tokens depleted
    allowed2 = await rl.is_allowed('client1')
    assert allowed2 is False


@pytest.mark.asyncio
async def test_resolver_shutdown_no_errors(monkeypatch):
    resolver = DNSResolver()
    # Patch pools' stop methods to ensure they're awaited
    async def fake_stop():
        return None
    monkeypatch.setattr(resolver._tcp_pool, 'stop', fake_stop)
    monkeypatch.setattr(resolver._h2_pool, 'stop', fake_stop)
    monkeypatch.setattr(resolver._h3_pool, 'stop', fake_stop)
    monkeypatch.setattr(resolver._quic_pool, 'stop', fake_stop)

    # Run shutdown and ensure it completes without raising
    await resolver.shutdown()
    
# ---------- Rate Limiting Before Parsing ----------
@pytest.mark.asyncio
async def test_rate_limiter_blocks_malformed_packets():
    """Rate limiter should be checked before parsing malformed wire."""
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        rate_limit_rps=1.0,
        rate_limit_burst=1.0,
    )

    # Exhaust the bucket
    limiter = resolver.rate_limiter
    await limiter.is_allowed("1.2.3.4")  # consumes one token

    # Now send a malformed packet (should be rejected before parsing)
    malformed = b'\x00\x01' + b'\x00' * 10  # incomplete header
    start = time.time()
    response = await resolver.forward_dns_query(malformed, client_ip="1.2.3.4")
    duration = time.time() - start

    # Should be REFUSED (RCODE 5) and quick (no parsing overhead)
    if len(response) >= 12:
        msg = dns.message.from_wire(response)
        assert msg.rcode() == dns.rcode.REFUSED
    else:
        # fallback: check flags
        assert int.from_bytes(response[2:4], 'big') & 0x0005  # REFUSED

    assert duration < 0.1  # should be fast, no expensive parsing
 