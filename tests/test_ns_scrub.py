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
    # Build a response with authority section containing NS for a different domain.
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)

    # Add an NS record for "other.com" (unsolicited)
    ns_rrset = dns.rrset.from_text("other.com.", 300, dns.rdataclass.IN, dns.rdatatype.NS, "ns.other.com.")
    resp.authority.append(ns_rrset)

    # Add a legitimate SOA record (should be kept)
    soa_rrset = dns.rrset.from_text(
        "example.com.", 300, dns.rdataclass.IN, dns.rdatatype.SOA,
        "ns.example.com. admin.example.com. 20250101 3600 1800 604800 60"
    )
    resp.authority.append(soa_rrset)

    wire = resp.to_wire()
    scrubbed = resolver._scrub_authority_section(wire, "example.com")
    msg = dns.message.from_wire(scrubbed)

    # NS for other.com should be removed
    ns_records = [rr for rr in msg.authority if rr.rdtype == dns.rdatatype.NS]
    assert len(ns_records) == 0
    # SOA should remain
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

    # NS for example.com (parent zone) - this is a valid delegation
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

    # Add an RRSIG record (non-NS)
    rrsig_rrset = dns.rrset.RRset(dns.name.from_text("example.com."), dns.rdataclass.IN, dns.rdatatype.RRSIG)
    rrsig_rrset.ttl = 300
    from dns.rdtypes.ANY.RRSIG import RRSIG
    rrsig = RRSIG(
        rdclass=dns.rdataclass.IN,
        rdtype=dns.rdatatype.RRSIG,
        covered=dns.rdatatype.A,
        algorithm=8,
        labels=1,
        orig_ttl=300,
        signature_expiration=2000000000,
        signature_inception=1000000000,
        key_tag=12345,
        signer_name=dns.name.from_text("example.com."),
        signature=b"dummy"
    )
    rrsig_rrset.add(rrsig)
    resp.authority.append(rrsig_rrset)

    wire = resp.to_wire()
    scrubbed = resolver._scrub_authority_section(wire, "example.com")
    msg = dns.message.from_wire(scrubbed)

    rrsig_records = [rr for rr in msg.authority if rr.rdtype == dns.rdatatype.RRSIG]
    assert len(rrsig_records) == 1


def test_scrub_removes_unsolicited_ns_with_glue(resolver):
    """Unsolicited NS records should be removed even if they have glue records."""
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)

    # Unsolicited NS with glue A record
    ns_rrset = dns.rrset.from_text("other.com.", 300, dns.rdataclass.IN, dns.rdatatype.NS, "ns.other.com.")
    resp.authority.append(ns_rrset)

    # Glue A record
    a_rrset = dns.rrset.from_text("ns.other.com.", 300, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
    resp.additional.append(a_rrset)

    wire = resp.to_wire()
    scrubbed = resolver._scrub_authority_section(wire, "example.com")
    msg = dns.message.from_wire(scrubbed)

    ns_records = [rr for rr in msg.authority if rr.rdtype == dns.rdatatype.NS]
    assert len(ns_records) == 0
    # The glue A record stays (it's in additional, and we don't scrub additional
    # to avoid breaking legitimate glue)
    # Note: We don't scrub additional section to avoid breaking legitimate glue,
    # and scrubbing additional is complex because it would require tracking which
    # NS records were removed. This is a design decision and is acceptable.