import asyncio
import dns.message
import dns.rdatatype
import pytest

from dosev.resolver import DNSResolver


@pytest.mark.asyncio
async def test_dnssec_lookup_handles_malformed_response(monkeypatch):
    resolver = DNSResolver(upstreams=[{"address": "127.0.0.1", "protocol": "udp", "ip": "127.0.0.1"}])

    async def fake_try_upstream(upstream, data, _health_check=False, _no_retry=False):
        # return deliberately malformed bytes
        return b'not a dns message'

    monkeypatch.setattr(resolver, "_try_upstream", fake_try_upstream)

    result = await resolver._dnssec_lookup('example.com', dns.rdatatype.A, dnssec_ok=True)
    assert result is None


@pytest.mark.asyncio
async def test_make_servfail_response_with_malformed_query():
    resolver = DNSResolver(upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}])
    # malformed query
    resp = resolver._make_servfail_response(b'invalid')
    assert isinstance(resp, (bytes, bytearray))
    assert resp != b''
 