"""
Tests for DNSSEC CD (Checking Disabled) flag support.
"""

import pytest
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rrset
from unittest.mock import AsyncMock, patch

from dosev.resolver import DNSResolver


@pytest.fixture
def resolver_with_dnssec():
    """Resolver with DNSSEC enabled and a mock trust anchor."""
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        dnssec_enabled=True,
        auto_update_trust_anchor=False,
    )
    resolver._dnssec_raw_anchors = {dns.name.root: b"dummy"}
    return resolver


@pytest.mark.asyncio
async def test_cd_flag_skips_validation(resolver_with_dnssec):
    """If CD flag is set, DNSSEC validation should be skipped."""
    query = dns.message.make_query("example.com", "A")
    query.flags |= 0x0010
    qwire = query.to_wire()

    resp = dns.message.make_response(query)
    rr = dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "93.184.216.34")
    resp.answer.append(rr)
    resp_wire = resp.to_wire()

    async def fake_try_upstream(upstream, data, _health_check=False, _no_retry=False):
        return resp_wire
    resolver_with_dnssec._try_upstream = fake_try_upstream

    validate_called = False
    async def fake_validate(qname, wire, requested):
        nonlocal validate_called
        validate_called = True
        return False, True
    resolver_with_dnssec._dnssec_validate = fake_validate

    result = await resolver_with_dnssec.forward_dns_query(qwire)
    msg = dns.message.from_wire(result)
    assert msg.rcode() == 0
    assert len(msg.answer) == 1
    assert validate_called is False


@pytest.mark.asyncio
async def test_no_cd_flag_triggers_validation(resolver_with_dnssec):
    """If CD flag is not set, validation should be attempted."""
    def fake_dnssec_requested(data):
        return True
    resolver_with_dnssec._dnssec_requested = fake_dnssec_requested

    query = dns.message.make_query("example.com", "A")
    query.flags &= ~0x0010
    qwire = query.to_wire()

    resp = dns.message.make_response(query)
    rr = dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "93.184.216.34")
    resp.answer.append(rr)
    resp_wire = resp.to_wire()

    async def fake_try_upstream(upstream, data, _health_check=False, _no_retry=False):
        return resp_wire
    resolver_with_dnssec._try_upstream = fake_try_upstream

    validate_called = False
    async def fake_validate(qname, wire, requested):
        nonlocal validate_called
        validate_called = True
        return False, True
    resolver_with_dnssec._dnssec_validate = fake_validate

    result = await resolver_with_dnssec.forward_dns_query(qwire)
    msg = dns.message.from_wire(result)
    assert msg.rcode() == 0
    assert len(msg.answer) == 1
    assert validate_called is True


@pytest.mark.asyncio
async def test_cd_flag_passthrough_ignores_bogus(resolver_with_dnssec):
    """Even if response is bogus, CD flag should return it without validation."""
    query = dns.message.make_query("example.com", "A")
    query.flags |= 0x0010
    qwire = query.to_wire()

    resp = dns.message.make_response(query)
    rr = dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "93.184.216.34")
    resp.answer.append(rr)
    resp_wire = resp.to_wire()

    async def fake_try_upstream(upstream, data, _health_check=False, _no_retry=False):
        return resp_wire
    resolver_with_dnssec._try_upstream = fake_try_upstream

    async def fake_validate(*args, **kwargs):
        raise Exception("Should not be called")
    resolver_with_dnssec._dnssec_validate = fake_validate

    result = await resolver_with_dnssec.forward_dns_query(qwire)
    msg = dns.message.from_wire(result)
    assert msg.rcode() == 0
    assert len(msg.answer) == 1