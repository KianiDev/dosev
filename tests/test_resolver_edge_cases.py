"""
Tests for edge cases, error paths, and untested branches in DNSResolver.
"""

import asyncio
import pytest
import socket
import ssl
import time
from unittest.mock import AsyncMock, MagicMock, patch, call

import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rrset
import dns.rcode
from dns.rdtypes.ANY.RRSIG import RRSIG

from dosev.resolver import DNSResolver, ConnectionPool, ClientPool, RateLimiter


# ---------- Helpers ----------
def make_a_response(qname: str, ip: str = "192.0.2.1", ttl: int = 60) -> bytes:
    if not qname.endswith('.'):
        qname = qname + '.'
    query = dns.message.make_query(qname, "A")
    resp = dns.message.make_response(query)
    rr = dns.rrset.from_text(qname, ttl, dns.rdataclass.IN, dns.rdatatype.A, ip)
    resp.answer.append(rr)
    return resp.to_wire()


def make_rrsig(covered_type: int, name: str) -> dns.rrset.RRset:
    if not name.endswith('.'):
        name = name + '.'
    rrsig_rrset = dns.rrset.RRset(dns.name.from_text(name), dns.rdataclass.IN, dns.rdatatype.RRSIG)
    rrsig_rrset.ttl = 300
    sig = RRSIG(
        dns.rdataclass.IN,
        dns.rdatatype.RRSIG,
        covered_type,
        8,  # algorithm
        1,  # labels
        300,  # original_ttl
        2000000000,  # expiration
        1000000000,  # inception
        12345,  # key_tag
        dns.name.from_text(name),
        b"dummy_signature"
    )
    rrsig_rrset.add(sig)
    return rrsig_rrset


# ---------- Forward UDP Edge Cases ----------
@pytest.mark.asyncio
async def test_forward_udp_timeout():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "port": 53, "ip": "1.1.1.1"}],
        udp_timeout=0.01
    )
    data = dns.message.make_query("example.com", "A").to_wire()

    loop = asyncio.get_running_loop()
    with patch.object(loop, "create_datagram_endpoint", new=AsyncMock()) as mock_endpoint:
        mock_transport = MagicMock()
        mock_protocol = MagicMock()
        mock_endpoint.return_value = (mock_transport, mock_protocol)

        with pytest.raises(asyncio.TimeoutError):
            await resolver._forward_udp(data, resolver.upstreams[0])


@pytest.mark.asyncio
async def test_forward_udp_connection_lost():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "port": 53, "ip": "1.1.1.1"}]
    )
    data = dns.message.make_query("example.com", "A").to_wire()
    loop = asyncio.get_running_loop()
    with patch.object(loop, "create_datagram_endpoint", new=AsyncMock(side_effect=ConnectionError("Lost"))):
        with pytest.raises(ConnectionError, match="Lost"):
            await resolver._forward_udp(data, resolver.upstreams[0])


# ---------- Forward TCP Edge Cases ----------
@pytest.mark.asyncio
async def test_forward_tcp_pool_reuse():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "tcp", "port": 53, "ip": "1.1.1.1"}]
    )
    data = dns.message.make_query("example.com", "A").to_wire()
    resp = make_a_response("example.com")

    async def fake_connect(*args, **kwargs):
        reader = AsyncMock()
        def readexactly_side_effect(n):
            if n == 2:
                return len(resp).to_bytes(2, "big")
            else:
                return resp
        reader.readexactly = AsyncMock(side_effect=readexactly_side_effect)
        writer = MagicMock()
        writer.is_closing = MagicMock(return_value=False)
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        return reader, writer

    with patch("asyncio.open_connection", side_effect=fake_connect):
        result = await resolver._forward_tcp(data, resolver.upstreams[0])
        assert result == resp

        result2 = await resolver._forward_tcp(data, resolver.upstreams[0])
        assert result2 == resp


@pytest.mark.asyncio
async def test_forward_tcp_closed_connection_creates_new():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "tcp", "port": 53, "ip": "1.1.1.1"}]
    )
    data = dns.message.make_query("example.com", "A").to_wire()
    resp = make_a_response("example.com")

    connect_count = 0

    async def fake_connect(*args, **kwargs):
        nonlocal connect_count
        connect_count += 1
        reader = AsyncMock()
        def readexactly_side_effect(n):
            if n == 2:
                return len(resp).to_bytes(2, "big")
            else:
                return resp
        reader.readexactly = AsyncMock(side_effect=readexactly_side_effect)
        writer = MagicMock()
        # First connection is closed, second is open
        if connect_count == 1:
            writer.is_closing = MagicMock(return_value=True)
            writer.close = MagicMock()
        else:
            writer.is_closing = MagicMock(return_value=False)
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        return reader, writer

    with patch("asyncio.open_connection", side_effect=fake_connect):
        result = await resolver._forward_tcp(data, resolver.upstreams[0])
        assert result == resp
        # The first connection was closed, so a second was created
        assert connect_count == 2


@pytest.mark.asyncio
async def test_forward_tcp_timeout():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "tcp", "port": 53, "ip": "1.1.1.1"}],
        tcp_timeout=0.01
    )
    data = dns.message.make_query("example.com", "A").to_wire()

    async def fake_connect(*args, **kwargs):
        reader = AsyncMock()
        reader.readexactly = AsyncMock(side_effect=asyncio.TimeoutError)
        writer = MagicMock()
        writer.is_closing = MagicMock(return_value=False)
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        return reader, writer

    with patch("asyncio.open_connection", side_effect=fake_connect):
        with pytest.raises(asyncio.TimeoutError):
            await resolver._forward_tcp(data, resolver.upstreams[0])


# ---------- Forward TLS Edge Cases ----------
@pytest.mark.asyncio
async def test_forward_tls_cert_verification_error():
    resolver = DNSResolver(
        upstreams=[{"address": "example.com", "protocol": "tls", "port": 853, "hostname": "example.com"}]
    )
    data = dns.message.make_query("example.com", "A").to_wire()

    with patch("asyncio.open_connection", new=AsyncMock(side_effect=ssl.SSLCertVerificationError("Invalid cert"))):
        with pytest.raises(ssl.SSLCertVerificationError):
            await resolver._forward_tls(data, resolver.upstreams[0])


@pytest.mark.asyncio
async def test_forward_tls_cert_pin_mismatch():
    resolver = DNSResolver(
        upstreams=[{"address": "example.com", "protocol": "tls", "port": 853, "hostname": "example.com"}],
        pinned_certs={"example.com": "abcdef1234567890"}
    )
    data = dns.message.make_query("example.com", "A").to_wire()
    resp = make_a_response("example.com")

    async def fake_connect(*args, **kwargs):
        reader = AsyncMock()
        def readexactly_side_effect(n):
            if n == 2:
                return len(resp).to_bytes(2, "big")
            else:
                return resp
        reader.readexactly = AsyncMock(side_effect=readexactly_side_effect)
        writer = MagicMock()
        writer.is_closing = MagicMock(return_value=False)
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        ssl_obj = MagicMock()
        ssl_obj.getpeercert.return_value = b"different_cert"
        writer.get_extra_info = MagicMock(return_value=ssl_obj)
        return reader, writer

    with patch("asyncio.open_connection", side_effect=fake_connect):
        with patch("hashlib.sha256") as mock_sha:
            mock_sha.return_value.hexdigest.return_value = "different_hash"
            with pytest.raises(Exception, match="Pinned certificate mismatch"):
                await resolver._forward_tls(data, resolver.upstreams[0])


@pytest.mark.asyncio
async def test_forward_tls_ssl_zero_return():
    resolver = DNSResolver(
        upstreams=[{"address": "example.com", "protocol": "tls", "port": 853}]
    )
    data = dns.message.make_query("example.com", "A").to_wire()

    with patch("asyncio.open_connection", new=AsyncMock(side_effect=ssl.SSLZeroReturnError("Connection closed"))):
        with pytest.raises(ssl.SSLZeroReturnError):
            await resolver._forward_tls(data, resolver.upstreams[0])


# ---------- Forward HTTPS Edge Cases ----------
@pytest.mark.asyncio
async def test_forward_https1_chunked_response():
    resolver = DNSResolver(
        upstreams=[{"address": "example.com", "protocol": "https", "port": 443, "hostname": "example.com"}]
    )
    data = dns.message.make_query("example.com", "A").to_wire()
    resp = make_a_response("example.com")

    # Build chunked response as a list of lines (each ending with \r\n)
    lines = [
        b"HTTP/1.1 200 OK\r\n",
        b"Transfer-Encoding: chunked\r\n",
        b"Content-Type: application/dns-message\r\n",
        b"\r\n",
        b"2\r\n",
        resp[:2] + b"\r\n",
        str(len(resp) - 2).encode() + b"\r\n",
        resp[2:] + b"\r\n",
        b"0\r\n",
        b"\r\n",
    ]

    async def fake_connect(*args, **kwargs):
        reader = AsyncMock()
        remaining_lines = lines.copy()
        async def readline_side_effect():
            if remaining_lines:
                return remaining_lines.pop(0)
            return b""
        reader.readline = AsyncMock(side_effect=readline_side_effect)
        reader.readexactly = AsyncMock(side_effect=[
            resp[:2],
            resp[2:],
        ])
        reader.readuntil = AsyncMock(return_value=b"\r\n")
        writer = MagicMock()
        writer.is_closing = MagicMock(return_value=False)
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        writer.wait_closed = AsyncMock()
        return reader, writer

    with patch("asyncio.open_connection", side_effect=fake_connect):
        result = await resolver._forward_https1(data, "example.com", 443, "example.com", "/dns-query", None)
        assert result == resp


@pytest.mark.asyncio
async def test_forward_https1_missing_content_length():
    resolver = DNSResolver(
        upstreams=[{"address": "example.com", "protocol": "https", "port": 443, "hostname": "example.com"}]
    )
    data = dns.message.make_query("example.com", "A").to_wire()

    lines = [
        b"HTTP/1.1 200 OK\r\n",
        b"Content-Type: application/dns-message\r\n",
        b"\r\n",
    ]

    async def fake_connect(*args, **kwargs):
        reader = AsyncMock()
        remaining_lines = lines.copy()
        async def readline_side_effect():
            if remaining_lines:
                return remaining_lines.pop(0)
            return b""
        reader.readline = AsyncMock(side_effect=readline_side_effect)
        writer = MagicMock()
        writer.is_closing = MagicMock(return_value=False)
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        writer.wait_closed = AsyncMock()
        return reader, writer

    with patch("asyncio.open_connection", side_effect=fake_connect):
        with pytest.raises(Exception, match="missing Content-Length and not chunked"):
            await resolver._forward_https1(data, "example.com", 443, "example.com", "/dns-query", None)


@pytest.mark.asyncio
async def test_forward_https2_pool_reuse():
    resolver = DNSResolver(
        upstreams=[{"address": "example.com", "protocol": "https", "port": 443, "hostname": "example.com"}],
        doh_timeout=1.0
    )
    data = dns.message.make_query("example.com", "A").to_wire()
    resp = make_a_response("example.com")

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=MagicMock(status_code=200, content=resp))
    mock_client.aclose = AsyncMock()

    with patch("httpx.AsyncClient", return_value=mock_client):
        result = await resolver._forward_https2(data, "example.com", 443, "example.com", "/dns-query", None)
        assert result == resp

        with patch.object(resolver._h2_pool, "get", new=AsyncMock(return_value=mock_client)):
            result2 = await resolver._forward_https2(data, "example.com", 443, "example.com", "/dns-query", None)
            assert result2 == resp


# ---------- DNSSEC Validation Edge Cases ----------
@pytest.mark.asyncio
async def test_dnssec_validation_bogus_signature():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        dnssec_enabled=True,
        auto_update_trust_anchor=False,
        dnssec_max_validations=10,
    )
    resolver._dnssec_raw_anchors = {dns.name.root: b"dummy"}

    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    rr = dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
    resp.answer.append(rr)
    resp.answer.append(make_rrsig(dns.rdatatype.A, "example.com"))

    with patch("dns.dnssec.validate", side_effect=dns.dnssec.ValidationFailure("bogus")):
        with pytest.raises(dns.dnssec.ValidationFailure):
            await resolver._dnssec_validate("example.com", resp.to_wire(), dnssec_requested=True)


@pytest.mark.asyncio
async def test_dnssec_validation_limit_exceeded():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        dnssec_enabled=True,
        auto_update_trust_anchor=False,
        dnssec_max_validations=1,
    )
    resolver._dnssec_raw_anchors = {dns.name.root: b"dummy"}

    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)

    rr1 = dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
    resp.answer.append(rr1)
    resp.answer.append(make_rrsig(dns.rdatatype.A, "example.com"))

    rr2 = dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.AAAA, "2001:db8::1")
    resp.answer.append(rr2)
    resp.answer.append(make_rrsig(dns.rdatatype.AAAA, "example.com"))

    with patch("dns.dnssec.validate", return_value=None):
        secure, insecure = await resolver._dnssec_validate("example.com", resp.to_wire(), dnssec_requested=True)
        assert secure is False
        assert insecure is True


@pytest.mark.asyncio
async def test_dnssec_validation_timeout():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        dnssec_enabled=True,
        auto_update_trust_anchor=False,
        dnssec_validation_timeout=0.01,
    )
    resolver._dnssec_raw_anchors = {dns.name.root: b"dummy"}

    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    rr = dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
    resp.answer.append(rr)
    resp.answer.append(make_rrsig(dns.rdatatype.A, "example.com"))

    def slow_validate(*args, **kwargs):
        import time
        time.sleep(0.1)
        return None

    with patch("dns.dnssec.validate", side_effect=slow_validate):
        secure, insecure = await resolver._dnssec_validate("example.com", resp.to_wire(), dnssec_requested=True)
        assert secure is False
        assert insecure is True


@pytest.mark.asyncio
async def test_dnssec_no_validation_when_disabled():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        dnssec_enabled=False,
    )
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    rr = dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
    resp.answer.append(rr)
    resp.answer.append(make_rrsig(dns.rdatatype.A, "example.com"))

    secure, insecure = await resolver._dnssec_validate("example.com", resp.to_wire(), dnssec_requested=True)
    assert secure is False
    assert insecure is True


# ---------- Optimistic Caching Edge Cases ----------
@pytest.mark.asyncio
async def test_optimistic_cache_serves_stale():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        optimistic_cache_enabled=True,
        optimistic_stale_max_age=3600,
        optimistic_stale_response_ttl=30,
    )
    data = dns.message.make_query("example.com", "A").to_wire()
    resp = make_a_response("example.com", ttl=60)
    key = resolver._build_cache_key(data)

    expiry = time.time() - 10
    stale_until = time.time() + 3600
    val = (resp, expiry, data, stale_until, False)
    await resolver._wire_cache_set(key, val)

    refresh_called = False
    async def fake_refresh(k, qd):
        nonlocal refresh_called
        refresh_called = True
    resolver._maybe_refresh_stale = fake_refresh

    result = await resolver._wire_cache_get_valid(key)
    assert result is not None
    cached_resp, dnssec_ok = result
    msg = dns.message.from_wire(cached_resp)
    assert msg.answer[0].ttl == 30

    await asyncio.sleep(0.1)
    assert refresh_called is True


@pytest.mark.asyncio
async def test_optimistic_cache_expires_completely():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        optimistic_cache_enabled=True,
        optimistic_stale_max_age=1,
        optimistic_stale_response_ttl=30,
    )
    data = dns.message.make_query("example.com", "A").to_wire()
    resp = make_a_response("example.com")
    key = resolver._build_cache_key(data)

    expiry = time.time() - 10
    stale_until = time.time() - 5
    val = (resp, expiry, data, stale_until, False)
    await resolver._wire_cache_set(key, val)

    result = await resolver._wire_cache_get_valid(key)
    assert result is None


# ---------- TCP Fallback ----------
@pytest.mark.asyncio
async def test_tcp_fallback_on_truncated_response():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "port": 53, "ip": "1.1.1.1"}],
        tcp_fallback_enabled=True,
    )
    data = dns.message.make_query("example.com", "A").to_wire()

    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    resp.flags |= dns.flags.TC
    truncated_wire = resp.to_wire()

    async def fake_forward_udp(*args, **kwargs):
        return truncated_wire
    resolver._forward_udp = fake_forward_udp

    tcp_called = False
    async def fake_forward_tcp(data, upstream):
        nonlocal tcp_called
        tcp_called = True
        return make_a_response("example.com")
    resolver._forward_tcp = fake_forward_tcp

    result = await resolver._try_upstream(resolver.upstreams[0], data)
    msg = dns.message.from_wire(result)
    assert msg.rcode() == dns.rcode.NOERROR
    assert len(msg.answer) == 1
    assert msg.answer[0].rdtype == dns.rdatatype.A
    assert tcp_called is True


@pytest.mark.asyncio
async def test_tcp_fallback_disabled():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "port": 53, "ip": "1.1.1.1"}],
        tcp_fallback_enabled=False,
    )
    data = dns.message.make_query("example.com", "A").to_wire()

    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    resp.flags |= dns.flags.TC
    truncated_wire = resp.to_wire()

    async def fake_forward_udp(*args, **kwargs):
        return truncated_wire
    resolver._forward_udp = fake_forward_udp

    tcp_called = False
    async def fake_forward_tcp(*args, **kwargs):
        nonlocal tcp_called
        tcp_called = True
        return make_a_response("example.com")
    resolver._forward_tcp = fake_forward_tcp

    result = await resolver._try_upstream(resolver.upstreams[0], data)
    assert result == truncated_wire
    assert tcp_called is False


# ---------- _set_tc_bit ----------
def test_set_tc_bit():
    resolver = DNSResolver()
    response = make_a_response("example.com")
    modified = resolver._set_tc_bit(response)
    flags = int.from_bytes(modified[2:4], 'big')
    assert flags & 0x0200 != 0


# ---------- _dnssec_requested ----------
def test_dnssec_requested_detects_do_flag():
    resolver = DNSResolver()
    query = dns.message.make_query("example.com", "A")
    # Manually set the DO flag using the OPT object
    opt = dns.message.OPT(rdclass=1232, options=[], flags=dns.flags.DO)
    query.opt = opt
    assert resolver._dnssec_requested(query.to_wire()) is True


def test_dnssec_requested_no_edns():
    resolver = DNSResolver()
    query = dns.message.make_query("example.com", "A")
    assert resolver._dnssec_requested(query.to_wire()) is False


# ---------- _extract_soa_minimum ----------
def test_extract_soa_minimum():
    resolver = DNSResolver()
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    soa = dns.rrset.from_text(
        "example.com.", 300, dns.rdataclass.IN, dns.rdatatype.SOA,
        "ns.example.com. admin.example.com. 20250101 3600 1800 604800 60"
    )
    resp.authority.append(soa)

    minimum = resolver._extract_soa_minimum(resp.to_wire())
    assert minimum == 60


def test_extract_soa_minimum_no_soa():
    resolver = DNSResolver()
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    rr = dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
    resp.answer.append(rr)

    minimum = resolver._extract_soa_minimum(resp.to_wire())
    assert minimum is None


# ---------- _extract_min_ttl ----------
def test_extract_min_ttl():
    resolver = DNSResolver()
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    rr1 = dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
    rr2 = dns.rrset.from_text("example.com.", 120, dns.rdataclass.IN, dns.rdatatype.AAAA, "2001:db8::1")
    resp.answer.append(rr1)
    resp.answer.append(rr2)

    min_ttl = resolver._extract_min_ttl(resp.to_wire())
    assert min_ttl == 60


# ---------- Rebinding Protection ----------
def test_apply_rebind_protection_strips_private():
    resolver = DNSResolver(
        rebind_protection_enabled=True,
        rebind_action="strip",
    )
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    rr1 = dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "8.8.8.8")
    rr2 = dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.168.1.1")
    resp.answer.append(rr1)
    resp.answer.append(rr2)

    result = resolver._apply_rebind_protection(resp.to_wire())
    msg = dns.message.from_wire(result)
    ips = [rr.to_text().split()[-1] for rr in msg.answer if rr.rdtype == dns.rdatatype.A]
    assert "8.8.8.8" in ips
    assert "192.168.1.1" not in ips


def test_apply_rebind_protection_blocks_all_private():
    resolver = DNSResolver(
        rebind_protection_enabled=True,
        rebind_action="block",
    )
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    rr = dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.168.1.1")
    resp.answer.append(rr)

    result = resolver._apply_rebind_protection(resp.to_wire())
    assert result is None


# ---------- _is_private_ip ----------
def test_is_private_ip():
    resolver = DNSResolver()
    assert resolver._is_private_ip("10.0.0.1") is True
    assert resolver._is_private_ip("192.168.1.1") is True
    assert resolver._is_private_ip("172.16.0.1") is True
    assert resolver._is_private_ip("127.0.0.1") is True
    assert resolver._is_private_ip("8.8.8.8") is False
    assert resolver._is_private_ip("::1") is True
    assert resolver._is_private_ip("2001:4860:4860::8888") is False
    assert resolver._is_private_ip("fe80::1") is True


# ---------- _split_hostport ----------
def test_split_hostport():
    resolver = DNSResolver()
    host, port = resolver._split_hostport("[2001:db8::1]:853")
    assert host == "2001:db8::1"
    assert port == 853

    host, port = resolver._split_hostport("example.com:443")
    assert host == "example.com"
    assert port == 443

    host, port = resolver._split_hostport("example.com")
    assert host == "example.com"
    assert port == 53


# ---------- Get Block Action ----------
def test_set_block_action():
    resolver = DNSResolver()
    resolver.set_block_action("REFUSED")
    assert resolver.get_block_action() == "REFUSED"

    resolver.set_block_action(None)
    assert resolver.get_block_action() == "NXDOMAIN"


# ---------- Build Local A Response ----------
def test_build_local_A_response():
    resolver = DNSResolver()
    query = dns.message.make_query("example.com", "A").to_wire()
    response = resolver._build_local_A_response(query, "192.0.2.1")
    msg = dns.message.from_wire(response)
    assert len(msg.answer) == 1
    assert msg.answer[0].rdtype == dns.rdatatype.A
    assert msg.answer[0][0].address == "192.0.2.1"


# ---------- Make NXDOMAIN Response ----------
def test_make_nxdomain_response_preserves_edns():
    resolver = DNSResolver()
    query = dns.message.make_query("example.com", "A")
    query.use_edns(payload=1232, options=[dns.edns.ECSOption("192.0.2.0", 24, 0)])
    qwire = query.to_wire()

    response = resolver._make_nxdomain_response(qwire)
    msg = dns.message.from_wire(response)
    assert msg.opt is not None
    assert msg.payload == 1232
    assert len(msg.options) == 1


def test_make_nxdomain_response_no_query():
    resolver = DNSResolver()
    response = resolver._make_nxdomain_response(b"")
    assert len(response) >= 12


# ---------- Is Negative Response ----------
def test_is_negative_response_nxdomain():
    resolver = DNSResolver()
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    resp.set_rcode(dns.rcode.NXDOMAIN)
    assert resolver._is_negative_response(resp.to_wire()) is True


def test_is_negative_response_noanswer():
    resolver = DNSResolver()
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    assert resolver._is_negative_response(resp.to_wire()) is True


def test_is_negative_response_with_answer():
    resolver = DNSResolver()
    resp = make_a_response("example.com")
    assert resolver._is_negative_response(resp) is False


def test_is_negative_response_malformed():
    resolver = DNSResolver()
    assert resolver._is_negative_response(b"") is False
    assert resolver._is_negative_response(b"short") is False


# ---------- Make Response from Hosts ----------
@pytest.mark.asyncio
async def test_hosts_map_response():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}]
    )
    await resolver.set_hosts_map({"example.com": ("192.0.2.1",)})

    query = dns.message.make_query("example.com", "A").to_wire()
    response = await resolver.forward_dns_query(query)
    msg = dns.message.from_wire(response)
    assert len(msg.answer) == 1
    assert msg.answer[0].rdtype == dns.rdatatype.A
    assert msg.answer[0][0].address == "192.0.2.1"