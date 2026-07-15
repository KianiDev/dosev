"""
Tests for scrubbing unsolicited NS records from authority section (CVE-2025-11411, RFC 2181).
"""

import pytest
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rrset
import dns.name
from dosev.resolver import DNSResolver


@pytest.fixture
def resolver():
    return DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        scrub_unsolicited_ns=True,
    )


def test_scrub_unsolicited_ns_removes_foreign_ns(resolver):
    """Unsolicited NS records not in the same bailiwick should be removed."""
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)

    ns_rrset = dns.rrset.from_text("other.com.", 300, dns.rdataclass.IN, dns.rdatatype.NS, "ns.other.com.")
    resp.authority.append(ns_rrset)

    soa_rrset = dns.rrset.from_text(
        "example.com.", 300, dns.rdataclass.IN, dns.rdatatype.SOA,
        "ns.example.com. admin.example.com. 20250101 3600 1800 604800 60"
    )
    resp.authority.append(soa_rrset)

    wire = resp.to_wire()
    scrubbed = resolver._scrub_authority_section(wire, "example.com")
    msg = dns.message.from_wire(scrubbed)

    ns_records = [rr for rr in msg.authority if rr.rdtype == dns.rdatatype.NS]
    assert len(ns_records) == 0
    soa_records = [rr for rr in msg.authority if rr.rdtype == dns.rdatatype.SOA]
    assert len(soa_records) == 1


def test_scrub_keeps_valid_ns_exact_match(resolver):
    """NS records exactly matching the qname should be kept."""
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)

    ns_rrset = dns.rrset.from_text("example.com.", 300, dns.rdataclass.IN, dns.rdatatype.NS, "ns.example.com.")
    resp.authority.append(ns_rrset)

    wire = resp.to_wire()
    scrubbed = resolver._scrub_authority_section(wire, "example.com")
    msg = dns.message.from_wire(scrubbed)

    ns_records = [rr for rr in msg.authority if rr.rdtype == dns.rdatatype.NS]
    assert len(ns_records) == 1


def test_scrub_keeps_valid_ns_parent_zone(resolver):
    """NS records for a parent zone should be kept (valid delegation)."""
    query = dns.message.make_query("www.example.com", "A")
    resp = dns.message.make_response(query)

    ns_rrset = dns.rrset.from_text("example.com.", 300, dns.rdataclass.IN, dns.rdatatype.NS, "ns.example.com.")
    resp.authority.append(ns_rrset)

    wire = resp.to_wire()
    scrubbed = resolver._scrub_authority_section(wire, "www.example.com")
    msg = dns.message.from_wire(scrubbed)

    ns_records = [rr for rr in msg.authority if rr.rdtype == dns.rdatatype.NS]
    assert len(ns_records) == 1


def test_scrub_keeps_root_ns(resolver):
    """Root NS records (name ".") should be kept."""
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)

    ns_rrset = dns.rrset.from_text(".", 300, dns.rdataclass.IN, dns.rdatatype.NS, "a.root-servers.net.")
    resp.authority.append(ns_rrset)

    wire = resp.to_wire()
    scrubbed = resolver._scrub_authority_section(wire, "example.com")
    msg = dns.message.from_wire(scrubbed)

    ns_records = [rr for rr in msg.authority if rr.rdtype == dns.rdatatype.NS]
    assert len(ns_records) == 1


def test_scrub_disabled(resolver):
    """When scrub_unsolicited_ns is False, no scrubbing occurs."""
    resolver.scrub_unsolicited_ns = False
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)

    ns_rrset = dns.rrset.from_text("other.com.", 300, dns.rdataclass.IN, dns.rdatatype.NS, "ns.other.com.")
    resp.authority.append(ns_rrset)

    wire = resp.to_wire()
    scrubbed = resolver._scrub_authority_section(wire, "example.com")
    msg = dns.message.from_wire(scrubbed)

    ns_records = [rr for rr in msg.authority if rr.rdtype == dns.rdatatype.NS]
    assert len(ns_records) == 1


def test_scrub_keeps_non_ns_records(resolver):
    """Non-NS records (SOA, RRSIG, etc.) should always be kept."""
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)

    from dns.rdtypes.ANY.RRSIG import RRSIG
    rrsig_rrset = dns.rrset.RRset(dns.name.from_text("example.com."), dns.rdataclass.IN, dns.rdatatype.RRSIG)
    rrsig_rrset.ttl = 300

    rrsig = RRSIG(
        dns.rdataclass.IN,
        dns.rdatatype.RRSIG,
        dns.rdatatype.A,   # type_covered
        8,                 # algorithm
        1,                 # labels
        300,               # original_ttl
        2000000000,        # expiration
        1000000000,        # inception
        12345,             # key_tag
        dns.name.from_text("example.com."),
        b"dummy"
    )
    rrsig_rrset.add(rrsig)
    resp.authority.append(rrsig_rrset)

    wire = resp.to_wire()
    scrubbed = resolver._scrub_authority_section(wire, "example.com")
    msg = dns.message.from_wire(scrubbed)

    rrsig_records = [rr for rr in msg.authority if rr.rdtype == dns.rdatatype.RRSIG]
    assert len(rrsig_records) == 1