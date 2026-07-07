import dns.message
import dns.rdatatype
import dns.rcode
import pytest
from dosev.resolver import DNSResolver


def test_split_hostport_ipv6_and_host():
    resolver = DNSResolver(upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}])
    host, port = resolver._split_hostport("[2001:db8::1]:853", default_port=53)
    assert host == "2001:db8::1"
    assert port == 853

    host, port = resolver._split_hostport("dns.example.com:443", default_port=53)
    assert host == "dns.example.com"
    assert port == 443

    host, port = resolver._split_hostport("example.com", default_port=53)
    assert host == "example.com"
    assert port == 53


def test_private_ip_detection():
    resolver = DNSResolver(upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}])
    assert resolver._is_private_ip("10.0.0.1") is True
    assert resolver._is_private_ip("192.168.1.1") is True
    assert resolver._is_private_ip("8.8.8.8") is False
    assert resolver._is_private_ip("::1") is True
    assert resolver._is_private_ip("2001:4860:4860::8888") is False


def test_build_block_response_zeroip_aaaa_disabled():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        disable_ipv6=True
    )
    query = dns.message.make_query("example.com", "AAAA").to_wire()
    response = resolver.build_block_response(query, action="ZEROIP")
    msg = dns.message.from_wire(response)
    assert msg.rcode() == dns.rcode.NXDOMAIN
    assert len(msg.answer) == 0


@pytest.mark.asyncio
async def test_update_config_changes_values():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        rate_limit_rps=0.0,
        rate_limit_burst=0.0
    )
    assert resolver.rate_limiter is None
    await resolver.update_config(rate_limit_rps=2.0, rate_limit_burst=2.0)
    assert resolver.rate_limit_rps == 2.0
    assert resolver.rate_limit_burst == 2.0
    assert resolver.rate_limiter is not None


def test_build_block_response_refused():
    resolver = DNSResolver(upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}])
    query = dns.message.make_query("example.com", "A").to_wire()
    response = resolver.build_block_response(query, action="REFUSED")
    msg = dns.message.from_wire(response)
    assert msg.rcode() == dns.rcode.REFUSED