import asyncio
import socket
import dns.message
import dns.rdatatype
import dns.rcode
import pytest
from dosev.resolver import DNSResolver


def test_split_hostport_ipv6_and_host():
    resolver = DNSResolver("1.1.1.1", protocol="udp")
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
    resolver = DNSResolver("1.1.1.1", protocol="udp")
    assert resolver._is_private_ip("10.0.0.1") is True
    assert resolver._is_private_ip("192.168.1.1") is True
    assert resolver._is_private_ip("8.8.8.8") is False
    assert resolver._is_private_ip("::1") is True
    assert resolver._is_private_ip("2001:4860:4860::8888") is False


def test_build_block_response_zeroip_aaaa_disabled():
    resolver = DNSResolver("1.1.1.1", protocol="udp", disable_ipv6=True)
    query = dns.message.make_query("example.com", "AAAA").to_wire()
    response = resolver.build_block_response(query, action="ZEROIP")
    msg = dns.message.from_wire(response)
    assert msg.rcode() == dns.rcode.NXDOMAIN
    assert len(msg.answer) == 0


@pytest.mark.asyncio
async def test_update_config_changes_values():
    resolver = DNSResolver("1.1.1.1", protocol="udp", rate_limit_rps=0.0, rate_limit_burst=0.0)
    assert resolver.rate_limiter is None
    await resolver.update_config(rate_limit_rps=2.0, rate_limit_burst=2.0)
    assert resolver.rate_limit_rps == 2.0
    assert resolver.rate_limit_burst == 2.0
    assert resolver.rate_limiter is not None


def test_build_block_response_refused():
    resolver = DNSResolver("1.1.1.1", protocol="udp")
    query = dns.message.make_query("example.com", "A").to_wire()
    response = resolver.build_block_response(query, action="REFUSED")
    msg = dns.message.from_wire(response)
    assert msg.rcode() == dns.rcode.REFUSED


@pytest.mark.asyncio
async def test_load_trust_anchors_builds_keyring_from_file(tmp_path):
    resolver = DNSResolver("1.1.1.1", protocol="udp", dnssec_enabled=True)
    anchor_path = tmp_path / "anchors.txt"
    anchor_path.write_text(
        ". 300 IN DNSKEY 257 3 8 "
        "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+Erq1sBvNaRfxv4d8+1o5RsS5rG3FJ0fruu1Wg+0JvN6sL5nlk46iS2BsUj8IYL0="
    )
    resolver.trust_anchors = str(anchor_path)
    resolver._load_trust_anchors()
    assert resolver._dnssec_raw_anchors is not None
    assert dns.name.root in resolver._dnssec_raw_anchors


@pytest.mark.asyncio
async def test_resolve_upstream_ip_all_fail(monkeypatch):
    resolver = DNSResolver("1.1.1.1", protocol="udp")
    resolver.bootstrap_servers = ["1.1.1.1:53"]

    async def fake_udp_query(ip, port, qname, qtype=1):
        return None
    monkeypatch.setattr(resolver, "_udp_query_a_or_aaaa", fake_udp_query)

    class FakeLoop:
        async def getaddrinfo(self, *args, **kwargs):
            raise socket.gaierror("No address found")

    loop = FakeLoop()
    monkeypatch.setattr(asyncio, "get_running_loop", lambda: loop)

    with pytest.raises(Exception, match="Unable to resolve upstream hostname"):
        await resolver._resolve_upstream_ip("nonexistent.example.com")


def test_apply_rebind_protection_strips_private_ips():
    resolver = DNSResolver("1.1.1.1", rebind_protection_enabled=True, rebind_action="strip")
    msg = dns.message.make_response(dns.message.make_query("example.com", "A"))
    msg.answer.append(dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "8.8.8.8"))
    msg.answer.append(dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.168.1.1"))
    wire = msg.to_wire()
    result = resolver._apply_rebind_protection(wire)
    result_msg = dns.message.from_wire(result)
    ips = [rr.to_text().split()[-1] for rr in result_msg.answer if rr.rdtype == dns.rdatatype.A]
    assert "8.8.8.8" in ips
    assert "192.168.1.1" not in ips


def test_apply_rebind_protection_blocks_when_action_block(monkeypatch):
    resolver = DNSResolver("1.1.1.1", rebind_protection_enabled=True, rebind_action="block")
    # Override the instance method directly
    def fake_is_private(ip):
        return True
    monkeypatch.setattr(resolver, "_is_private_ip", fake_is_private)
    msg = dns.message.make_response(dns.message.make_query("example.com", "A"))
    msg.answer.append(dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.168.1.1"))
    wire = msg.to_wire()
    result = resolver._apply_rebind_protection(wire)
    assert result is None