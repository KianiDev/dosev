"""
Tests for DNSSEC KeyTrap mitigation (CVE-2023-50387):
- Limits on number of validations per response
- Limits on DNSKEY records processed
- Timeout on validation operations
"""

import asyncio
import pytest
import tempfile
import os
import time
import dns.message
import dns.dnssec
import dns.rdatatype
import dns.rdataclass
import dns.rrset
import dns.name
from unittest.mock import patch, MagicMock, AsyncMock

from dosev.resolver import DNSResolver


@pytest.fixture
def resolver():
    """Resolver with DNSSEC enabled and KeyTrap limits configured."""
    return DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        dnssec_enabled=True,
        auto_update_trust_anchor=False,
        dnssec_max_validations=2,
        dnssec_max_dnskey_records=1,
        dnssec_validation_timeout=0.1,
        trust_anchors=None,
    )


def create_rrsig(covered_type: int, name: str) -> dns.rrset.RRset:
    """Helper to create a valid RRSIG RRset for testing."""
    from dns.rdtypes.ANY.RRSIG import RRSIG

    rrsig_rrset = dns.rrset.RRset(
        dns.name.from_text(name),
        dns.rdataclass.IN,
        dns.rdatatype.RRSIG
    )
    rrsig_rrset.ttl = 300

    # RRSIG constructor: rdclass, rdtype, type_covered, algorithm, labels,
    # original_ttl, expiration, inception, key_tag, signer, signature
    rrsig = RRSIG(
        dns.rdataclass.IN,
        dns.rdatatype.RRSIG,
        covered_type,          # type_covered (positional)
        8,                     # algorithm (RSA-SHA256)
        1,                     # labels
        300,                   # original_ttl
        2000000000,            # expiration
        1000000000,            # inception
        12345,                 # key_tag
        dns.name.from_text(name),  # signer
        b"dummy_signature"     # signature
    )
    rrsig_rrset.add(rrsig)
    return rrsig_rrset


@pytest.mark.asyncio
async def test_dnssec_max_validations_limit(resolver):
    """
    If a response has more RRsets requiring validation than max_validations,
    the resolver should treat the response as insecure after exceeding the limit.
    """
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)

    # Add 3 A records with RRSIGs
    for i in range(3):
        name = f"example{i}.com."
        a_rrset = dns.rrset.from_text(name, 300, dns.rdataclass.IN, dns.rdatatype.A, f"192.0.2.{i+1}")
        resp.answer.append(a_rrset)
        resp.answer.append(create_rrsig(dns.rdatatype.A, name))

    validate_calls = 0

    def fake_validate(rrset, sig, anchors):
        nonlocal validate_calls
        validate_calls += 1
        return

    wire = resp.to_wire()
    qname = "example.com"

    with patch('dns.dnssec.validate', side_effect=fake_validate):
        secure, insecure = await resolver._dnssec_validate(qname, wire, dnssec_requested=True)

        # Should return insecure (False, True) because limit was exceeded
        assert secure is False
        assert insecure is True

        # validate should have been called exactly max_validations (2) times
        assert validate_calls == 2


@pytest.mark.asyncio
async def test_dnssec_keytrap_dnskey_limit():
    """
    Test that only dnssec_max_dnskey_records DNSKEYs are loaded per domain.
    """
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write(""". 3600 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+Erq1sBvNaRfxv4d8+1o5RsS5rG3FJ0fruu1Wg+0JvN6sL5nlk46iS2BsUj8IYL0=\n""")
        f.write(""". 3600 IN DNSKEY 257 3 8 AwEAAdummy1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n""")
        f.write(""". 3600 IN DNSKEY 257 3 8 AwEAAdummy2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n""")
        fname = f.name

    try:
        resolver = DNSResolver(
            upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
            dnssec_enabled=True,
            auto_update_trust_anchor=False,
            dnssec_max_dnskey_records=1,
            trust_anchors=fname,
        )

        resolver._load_trust_anchors()

        assert resolver._dnssec_raw_anchors is not None
        root_anchor = resolver._dnssec_raw_anchors.get(dns.name.root)
        assert root_anchor is not None
        # Should be limited to 1 DNSKEY
        assert len(root_anchor) == 1

    finally:
        os.unlink(fname)


@pytest.mark.asyncio
async def test_dnssec_keytrap_validation_timeout(resolver):
    """
    If validation takes longer than dnssec_validation_timeout, it should
    time out and return insecure (False, True).
    """
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)

    a_rrset = dns.rrset.from_text("example.com.", 300, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
    resp.answer.append(a_rrset)
    resp.answer.append(create_rrsig(dns.rdatatype.A, "example.com."))

    wire = resp.to_wire()
    qname = "example.com"

    # Must be synchronous because dns.dnssec.validate is called via run_in_executor
    def slow_validate(rrset, sig, anchors):
        time.sleep(0.5)  # synchronous sleep
        return

    with patch('dns.dnssec.validate', side_effect=slow_validate):
        secure, insecure = await resolver._dnssec_validate(qname, wire, dnssec_requested=True)
        # Should return insecure (False, True) due to timeout
        assert secure is False
        assert insecure is True


@pytest.mark.asyncio
async def test_dnssec_no_validation_when_cd_flag_set():
    """
    When the CD (Checking Disabled) flag is set, validation should be skipped.
    """
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        dnssec_enabled=True,
        auto_update_trust_anchor=False,
    )
    resolver._dnssec_raw_anchors = {dns.name.root: b"dummy"}

    query = dns.message.make_query("example.com", "A")
    query.flags |= 0x0010  # CD flag
    qwire = query.to_wire()

    validate_called = False

    def fake_validate(rrset, sig, anchors):
        nonlocal validate_called
        validate_called = True
        return

    resp = dns.message.make_response(query)
    a_rrset = dns.rrset.from_text("example.com.", 300, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
    resp.answer.append(a_rrset)
    resp.answer.append(create_rrsig(dns.rdatatype.A, "example.com."))
    wire = resp.to_wire()

    async def fake_try_upstream(upstream, data, _health_check=False, _no_retry=False):
        return wire
    resolver._try_upstream = fake_try_upstream

    with patch('dns.dnssec.validate', side_effect=fake_validate):
        result = await resolver.forward_dns_query(qwire)
        # validate should NOT have been called because CD flag is set
        assert validate_called is False
        msg = dns.message.from_wire(result)
        assert msg.rcode() == 0