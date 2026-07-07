"""
Tests for IPv6 stripping feature.
"""

import pytest
import dns.message
import dns.rdatatype
from dosev.resolver import DNSResolver


def test_strip_ipv6_records():
    resolver = DNSResolver(strip_ipv6_records=True)
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    resp.answer.append(dns.rrset.from_text("example.com.", 300, dns.rdataclass.IN, dns.rdatatype.A, "93.184.216.34"))
    resp.answer.append(dns.rrset.from_text("example.com.", 300, dns.rdataclass.IN, dns.rdatatype.AAAA, "2001:db8::1"))
    wire = resp.to_wire()
    stripped = resolver._strip_ipv6_records(wire)
    msg = dns.message.from_wire(stripped)
    aaaa_rrs = [rr for rr in msg.answer if rr.rdtype == dns.rdatatype.AAAA]
    assert len(aaaa_rrs) == 0
    a_rrs = [rr for rr in msg.answer if rr.rdtype == dns.rdatatype.A]
    assert len(a_rrs) == 1


def test_strip_ipv6_records_disabled():
    resolver = DNSResolver(strip_ipv6_records=False)
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    resp.answer.append(dns.rrset.from_text("example.com.", 300, dns.rdataclass.IN, dns.rdatatype.A, "93.184.216.34"))
    resp.answer.append(dns.rrset.from_text("example.com.", 300, dns.rdataclass.IN, dns.rdatatype.AAAA, "2001:db8::1"))
    wire = resp.to_wire()
    stripped = resolver._strip_ipv6_records(wire)
    assert stripped == wire