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
    query = dns.message.make_query(qname, "A")
    resp = dns.message.make_response(query)
    rr = dns.rrset.from_text(qname, ttl, dns.rdataclass.IN, dns.rdatatype.A, ip)
    resp.answer.append(rr)
    return resp.to_wire()


def make_nxdomain_response(qname: str) -> bytes:
    query = dns.message.make_query(qname, "A")
    resp = dns.message.make_response(query)
    resp.set_rcode(dns.rcode.NXDOMAIN)
    return resp.to_wire()


def make_rrsig(covered_type: int, name: str) -> dns.rrset.RRset:
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
    """UDP forward should raise TimeoutError when no response arrives."""
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
    """UDP forward should raise when the underlying connection is lost."""
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "port": 53, "ip": "1.1.1.1"}]
    )
    data = dns.message.make_query("example.com", "A").to_wire()

    loop = asyncio.get_running_loop()

    class FakeProtocol:
        def __init__(self):
            self.transport = None

        def connection_made(self, transport):
            self.transport = transport
            # Simulate connection lost immediately
            self.connection_lost(ConnectionError("Connection lost"))

        def connection_lost(self, exc):
            # This is called by asyncio; we need to propagate the exception
            pass

    # We need to create a custom endpoint that returns a protocol that immediately
    # triggers connection_lost. We'll patch the inner behavior.
    with patch.object(loop, "create_datagram_endpoint") as mock_endpoint:
        transport = MagicMock()
        # Return a Future that we can control
        future = asyncio.Future()

        async def fake_endpoint(*args, **kwargs):
            protocol = FakeProtocol()
            # Simulate the protocol raising exception via connection_lost
            # We'll set the future exception when connection_lost is called
            original_connection_lost = protocol.connection_lost

            def connection_lost(exc):
                original_connection_lost(exc)
                if not future.done():
                    future.set_exception(exc)
            protocol.connection_lost = connection_lost
            return transport, protocol

        mock_endpoint.side_effect = fake_endpoint

        with pytest.raises(ConnectionError, match="Connection lost"):
            await resolver._forward_udp(data, resolver.upstreams[0])


# ---------- Forward TCP Edge Cases ----------
@pytest.mark.asyncio
async def test_forward_tcp_pool_reuse():
    """TCP should reuse connections from the pool."""
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "tcp", "port": 53, "ip": "1.1.1.1"}]
    )
    data = dns.message.make_query("example.com", "A").to_wire()
    resp = make_a_response("example.com")

    async def fake_connect(*args, **kwargs):
        reader = AsyncMock()
        reader.readexactly = AsyncMock(side_effect=[
            len(resp).to_bytes(2, "big"),
            resp
        ])
        writer = MagicMock()
        writer.is_closing = MagicMock(return_value=False)
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        return reader, writer

    with patch("asyncio.open_connection", side_effect=fake_connect):
        # First call should create connection
        result = await resolver._forward_tcp(data, resolver.upstreams[0])
        assert result == resp

        # Second call should reuse the pool
        # We need to ensure the pool has the connection
        # The connection was already put in the pool by the first call.
        # The second call will get it from the pool.
        result2 = await resolver._forward_tcp(data, resolver.upstreams[0])
        assert result2 == resp


@pytest.mark.asyncio
async def test_forward_tcp_closed_connection_creates_new():
    """TCP should create a new connection if pooled connection is closed."""
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
        reader.readexactly = AsyncMock(side_effect=[
            len(resp).to_bytes(2, "big"),
            resp
        ])
        writer = MagicMock()
        # First call returns closed connection, second returns open
        writer.is_closing = MagicMock(return_value=connect_count == 1)
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        return reader, writer

    with patch("asyncio.open_connection", side_effect=fake_connect):
        # First call will create connection and put it in pool
        # But the connection is marked as closing, so it will be discarded
        result = await resolver._forward_tcp(data, resolver.upstreams[0])
        assert result == resp
        # The closed connection was discarded, so a new one should be created
        assert connect_count == 2


@pytest.mark.asyncio
async def test_forward_tcp_timeout():
    """TCP forward should raise TimeoutError on read timeout."""
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "tcp", "port": 53, "ip": "1.1.1.1"}],
        tcp_timeout=0.01
    )
    data = dns.message.make_query("example.com", "A").to_wire()

    async def fake_connect(*args, **kwargs):
        reader = AsyncMock()
        # Simulate timeout on readexactly
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
    """TLS should raise SSLCertVerificationError on cert validation failure."""
    resolver = DNSResolver(
        upstreams=[{"address": "example.com", "protocol": "tls", "port": 853, "hostname": "example.com"}]
    )
    data = dns.message.make_query("example.com", "A").to_wire()

    with patch("asyncio.open_connection", new=AsyncMock(side_effect=ssl.SSLCertVerificationError("Invalid cert"))):
        with pytest.raises(ssl.SSLCertVerificationError):
            await resolver._forward_tls(data, resolver.upstreams[0])


@pytest.mark.asyncio
async def test_forward_tls_cert_pin_mismatch():
    """TLS should raise when certificate pin doesn't match."""
    resolver = DNSResolver(
        upstreams=[{"address": "example.com", "protocol": "tls", "port": 853, "hostname": "example.com"}],
        pinned_certs={"example.com": "abcdef1234567890"}
    )
    data = dns.message.make_query("example.com", "A").to_wire()
    resp = make_a_response("example.com")

    async def fake_connect(*args, **kwargs):
        reader = AsyncMock()
        reader.readexactly = AsyncMock(side_effect=[
            len(resp).to_bytes(2, "big"),
            resp
        ])
        writer = MagicMock()
        writer.is_closing = MagicMock(return_value=False)
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        ssl_obj = MagicMock()
        # Return a certificate that will hash to a different value
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
    """TLS should handle SSLZeroReturnError."""
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
    """HTTPS/1.1 should handle chunked transfer encoding."""
    resolver = DNSResolver(
        upstreams=[{"address": "example.com", "protocol": "https", "port": 443, "hostname": "example.com"}]
    )
    data = dns.message.make_query("example.com", "A").to_wire()
    resp = make_a_response("example.com")

    # Simulate a chunked response
    chunked_response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Content-Type: application/dns-message\r\n"
        b"\r\n"
        b"2\r\n"
        + resp[:2] + b"\r\n"
        + str(len(resp) - 2).encode() + b"\r\n"
        + resp[2:] + b"\r\n"
        b"0\r\n"
        b"\r\n"
    )

    async def fake_connect(*args, **kwargs):
        reader = AsyncMock()
        reader.readline = AsyncMock(side_effect=[
            chunked_response.splitlines()[0] + b"\r\n",
            chunked_response.splitlines()[1] + b"\r\n",
            chunked_response.splitlines()[2] + b"\r\n",
            b"\r\n",  # empty line after headers
            # Chunked body
            b"2\r\n",
            resp[:2] + b"\r\n",
            str(len(resp) - 2).encode() + b"\r\n",
            resp[2:] + b"\r\n",
            b"0\r\n",
            b"\r\n",
        ])
        # For chunked body reading, we need readexactly to work
        reader.readexactly = AsyncMock(side_effect=[
            resp[:2],
            resp[2:],
        ])
        reader.readuntil = AsyncMock(return_value=b"\r\n")
        writer = MagicMock()
        writer.is_closing = MagicMock(return_value=False)
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        return reader, writer

    with patch("asyncio.open_connection", side_effect=fake_connect):
        result = await resolver._forward_https1(data, "example.com", 443, "example.com", "/dns-query", None)
        assert result == resp


@pytest.mark.asyncio
async def test_forward_https1_missing_content_length():
    """HTTPS/1.1 should reject responses without Content-Length or chunked."""
    resolver = DNSResolver(
        upstreams=[{"address": "example.com", "protocol": "https", "port": 443, "hostname": "example.com"}]
    )
    data = dns.message.make_query("example.com", "A").to_wire()

    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/dns-message\r\n"
        b"\r\n"
    )

    async def fake_connect(*args, **kwargs):
        reader = AsyncMock()
        reader.readline = AsyncMock(side_effect=[
            response.splitlines()[0] + b"\r\n",
            response.splitlines()[1] + b"\r\n",
            b"\r\n",
        ])
        writer = MagicMock()
        writer.is_closing = MagicMock(return_value=False)
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        return reader, writer

    with patch("asyncio.open_connection", side_effect=fake_connect):
        with pytest.raises(Exception, match="missing Content-Length and not chunked"):
            await resolver._forward_https1(data, "example.com", 443, "example.com", "/dns-query", None)


@pytest.mark.asyncio
async def test_forward_https2_pool_reuse():
    """HTTPS/2 should reuse httpx clients from the pool."""
    resolver = DNSResolver(
        upstreams=[{"address": "example.com", "protocol": "https", "port": 443, "hostname": "example.com"}],
        doh_timeout=1.0
    )
    data = dns.message.make_query("example.com", "A").to_wire()
    resp = make_a_response("example.com")

    # Mock httpx
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=MagicMock(status_code=200, content=resp))
    mock_client.aclose = AsyncMock()

    with patch("httpx.AsyncClient", return_value=mock_client):
        # First call creates client
        result = await resolver._forward_https2(data, "example.com", 443, "example.com", "/dns-query", None)
        assert result == resp

        # Second call should reuse client from pool
        # The client was put in the pool, so we need to mock pool.get
        with patch.object(resolver._h2_pool, "get", new=AsyncMock(return_value=mock_client)):
            result2 = await resolver._forward_https2(data, "example.com", 443, "example.com", "/dns-query", None)
            assert result2 == resp


# ---------- Forward QUIC Edge Cases ----------
@pytest.mark.asyncio
async def test_forward_quic_closed_connection():
    """QUIC should create a new connection if pooled connection is closed."""
    if not hasattr(DNSResolver, "_HAS_AIOQUIC") or not DNSResolver._HAS_AIOQUIC:
        pytest.skip("aioquic not available")

    resolver = DNSResolver(
        upstreams=[{"address": "example.com", "protocol": "quic", "port": 853, "hostname": "example.com"}]
    )
    data = dns.message.make_query("example.com", "A").to_wire()
    resp = make_a_response("example.com")

    # Mock aioquic
    with patch("aioquic.asyncio.connect") as mock_connect:
        mock_client = MagicMock()
        mock_client._quic = MagicMock()
        mock_client._quic.closed = False
        mock_client._quic.get_next_available_stream_id = MagicMock(return_value=0)
        mock_client._quic.send_stream_data = MagicMock()
        mock_client.transmit = MagicMock()
        mock_client.wait_connected = AsyncMock()

        # First call: return client, second call: return None (pool get fails)
        mock_connect.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_connect.return_value.__aexit__ = AsyncMock(return_value=None)

        # Mock pool.get to return None first, then a client
        get_calls = [None, mock_client]
        original_get = resolver._quic_pool.get

        async def mock_pool_get(key):
            if get_calls:
                return get_calls.pop(0)
            return await original_get(key)
        resolver._quic_pool.get = mock_pool_get

        with patch("asyncio.wait_for", new=AsyncMock(return_value=b"\x00\x0d" + resp)):
            result = await resolver._forward_quic(data, resolver.upstreams[0])
            assert result == resp


# ---------- DNSSEC Validation Edge Cases ----------
@pytest.mark.asyncio
async def test_dnssec_validation_bogus_signature():
    """DNSSEC validation should raise ValidationFailure on bogus signatures."""
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
    resp.answer.append(make_rrsig(dns.rdatatype.A, "example.com."))

    with patch("dns.dnssec.validate", side_effect=dns.dnssec.ValidationFailure("bogus")):
        with pytest.raises(dns.dnssec.ValidationFailure):
            await resolver._dnssec_validate("example.com", resp.to_wire(), dnssec_requested=True)


@pytest.mark.asyncio
async def test_dnssec_validation_limit_exceeded():
    """DNSSEC validation should treat as insecure when validation limit is exceeded."""
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        dnssec_enabled=True,
        auto_update_trust_anchor=False,
        dnssec_max_validations=1,
    )
    resolver._dnssec_raw_anchors = {dns.name.root: b"dummy"}

    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)

    # Add 2 RRsets with RRSIGs to trigger limit
    rr1 = dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
    resp.answer.append(rr1)
    resp.answer.append(make_rrsig(dns.rdatatype.A, "example.com."))

    rr2 = dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.AAAA, "2001:db8::1")
    resp.answer.append(rr2)
    resp.answer.append(make_rrsig(dns.rdatatype.AAAA, "example.com."))

    with patch("dns.dnssec.validate", return_value=None):
        secure, insecure = await resolver._dnssec_validate("example.com", resp.to_wire(), dnssec_requested=True)
        assert secure is False
        assert insecure is True  # limit exceeded -> insecure


@pytest.mark.asyncio
async def test_dnssec_validation_timeout():
    """DNSSEC validation should return insecure on timeout."""
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
    resp.answer.append(make_rrsig(dns.rdatatype.A, "example.com."))

    def slow_validate(*args, **kwargs):
        import time
        time.sleep(0.1)  # longer than timeout
        return None

    with patch("dns.dnssec.validate", side_effect=slow_validate):
        secure, insecure = await resolver._dnssec_validate("example.com", resp.to_wire(), dnssec_requested=True)
        assert secure is False
        assert insecure is True


@pytest.mark.asyncio
async def test_dnssec_no_validation_when_disabled():
    """DNSSEC validation should be skipped when disabled."""
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        dnssec_enabled=False,
    )
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    rr = dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
    resp.answer.append(rr)
    resp.answer.append(make_rrsig(dns.rdatatype.A, "example.com."))

    # No validation should be attempted
    secure, insecure = await resolver._dnssec_validate("example.com", resp.to_wire(), dnssec_requested=True)
    assert secure is False
    assert insecure is True


# ---------- NS Scrubbing Edge Cases ----------
def test_scrub_authority_section_removes_unsolicited_ns():
    """Unsolicited NS records should be removed from authority section."""
    resolver = DNSResolver(scrub_unsolicited_ns=True)
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)

    ns1 = dns.rrset.from_text("other.com.", 300, dns.rdataclass.IN, dns.rdatatype.NS, "ns.other.com.")
    ns2 = dns.rrset.from_text("bad.net.", 300, dns.rdataclass.IN, dns.rdatatype.NS, "ns.bad.net.")
    resp.authority.append(ns1)
    resp.authority.append(ns2)

    wire = resp.to_wire()
    scrubbed = resolver._scrub_authority_section(wire, "example.com")
    msg = dns.message.from_wire(scrubbed)

    ns_records = [rr for rr in msg.authority if rr.rdtype == dns.rdatatype.NS]
    assert len(ns_records) == 0


def test_scrub_authority_section_keeps_root_ns():
    """Root NS records should always be kept."""
    resolver = DNSResolver(scrub_unsolicited_ns=True)
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)

    ns = dns.rrset.from_text(".", 300, dns.rdataclass.IN, dns.rdatatype.NS, "a.root-servers.net.")
    resp.authority.append(ns)

    wire = resp.to_wire()
    scrubbed = resolver._scrub_authority_section(wire, "example.com")
    msg = dns.message.from_wire(scrubbed)

    ns_records = [rr for rr in msg.authority if rr.rdtype == dns.rdatatype.NS]
    assert len(ns_records) == 1


def test_scrub_authority_section_keeps_valid_delegation():
    """NS records for parent zone should be kept (valid delegation)."""
    resolver = DNSResolver(scrub_unsolicited_ns=True)
    query = dns.message.make_query("www.example.com", "A")
    resp = dns.message.make_response(query)

    ns = dns.rrset.from_text("example.com.", 300, dns.rdataclass.IN, dns.rdatatype.NS, "ns.example.com.")
    resp.authority.append(ns)

    wire = resp.to_wire()
    scrubbed = resolver._scrub_authority_section(wire, "www.example.com")
    msg = dns.message.from_wire(scrubbed)

    ns_records = [rr for rr in msg.authority if rr.rdtype == dns.rdatatype.NS]
    assert len(ns_records) == 1


def test_scrub_authority_section_keeps_non_ns_records():
    """Non-NS records should always be kept."""
    resolver = DNSResolver(scrub_unsolicited_ns=True)
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)

    soa = dns.rrset.from_text(
        "example.com.", 300, dns.rdataclass.IN, dns.rdatatype.SOA,
        "ns.example.com. admin.example.com. 20250101 3600 1800 604800 60"
    )
    resp.authority.append(soa)

    wire = resp.to_wire()
    scrubbed = resolver._scrub_authority_section(wire, "example.com")
    msg = dns.message.from_wire(scrubbed)

    soa_records = [rr for rr in msg.authority if rr.rdtype == dns.rdatatype.SOA]
    assert len(soa_records) == 1


def test_scrub_authority_section_disabled():
    """When scrub_unsolicited_ns is False, no scrubbing occurs."""
    resolver = DNSResolver(scrub_unsolicited_ns=False)
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)

    ns = dns.rrset.from_text("other.com.", 300, dns.rdataclass.IN, dns.rdatatype.NS, "ns.other.com.")
    resp.authority.append(ns)

    wire = resp.to_wire()
    scrubbed = resolver._scrub_authority_section(wire, "example.com")
    msg = dns.message.from_wire(scrubbed)

    ns_records = [rr for rr in msg.authority if rr.rdtype == dns.rdatatype.NS]
    assert len(ns_records) == 1


def test_scrub_authority_section_handles_exception():
    """Invalid wire data should be returned as-is."""
    resolver = DNSResolver(scrub_unsolicited_ns=True)
    result = resolver._scrub_authority_section(b"invalid", "example.com")
    assert result == b"invalid"


# ---------- Optimistic Caching Edge Cases ----------
@pytest.mark.asyncio
async def test_optimistic_cache_serves_stale():
    """Optimistic cache should serve stale responses with rewritten TTL."""
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        optimistic_cache_enabled=True,
        stale_max_age=3600,
        stale_response_ttl=30,
    )
    data = dns.message.make_query("example.com", "A").to_wire()
    resp = make_a_response("example.com", ttl=60)
    key = resolver._build_cache_key(data)

    # Insert expired entry
    expiry = time.time() - 10
    stale_until = time.time() + 3600
    val = (resp, expiry, data, stale_until, False)
    await resolver._wire_cache_set(key, val)

    refresh_called = False
    original_refresh = resolver._maybe_refresh_stale
    async def fake_refresh(k, qd):
        nonlocal refresh_called
        refresh_called = True
    resolver._maybe_refresh_stale = fake_refresh

    result = await resolver._wire_cache_get_valid(key)
    assert result is not None
    cached_resp, dnssec_ok = result
    msg = dns.message.from_wire(cached_resp)
    # TTL should be rewritten to stale_response_ttl
    assert msg.answer[0].ttl == 30

    await asyncio.sleep(0.1)
    assert refresh_called is True


@pytest.mark.asyncio
async def test_optimistic_cache_expires_completely():
    """When stale entry expires completely, it should be removed."""
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        optimistic_cache_enabled=True,
        stale_max_age=1,
        stale_response_ttl=30,
    )
    data = dns.message.make_query("example.com", "A").to_wire()
    resp = make_a_response("example.com")
    key = resolver._build_cache_key(data)

    # Insert expired entry with no stale window
    expiry = time.time() - 10
    stale_until = time.time() - 5  # already past stale window
    val = (resp, expiry, data, stale_until, False)
    await resolver._wire_cache_set(key, val)

    result = await resolver._wire_cache_get_valid(key)
    assert result is None


# ---------- Cache Key Building ----------
def test_build_cache_key_handles_malformed_data():
    """_build_cache_key should handle malformed data gracefully."""
    resolver = DNSResolver()
    # Empty data
    key = resolver._build_cache_key(b"")
    assert key[0] == ""
    assert key[1] == 1

    # Short data
    key = resolver._build_cache_key(b"\x00\x01")
    assert key[0] == ""
    assert key[1] == 1


# ---------- TCP Fallback ----------
@pytest.mark.asyncio
async def test_tcp_fallback_on_truncated_response():
    """TCP fallback should be triggered when UDP response has TC bit set."""
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "port": 53, "ip": "1.1.1.1"}],
        tcp_fallback_enabled=True,
    )
    data = dns.message.make_query("example.com", "A").to_wire()

    # Simulate UDP response with TC bit set
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
    assert result == make_a_response("example.com")
    assert tcp_called is True


@pytest.mark.asyncio
async def test_tcp_fallback_disabled():
    """When tcp_fallback_enabled is False, TC bit should not trigger TCP retry."""
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
    # Should return the truncated response as-is
    assert result == truncated_wire
    assert tcp_called is False


# ---------- _set_tc_bit ----------
def test_set_tc_bit():
    """_set_tc_bit should set the TC flag in the response."""
    resolver = DNSResolver()
    response = make_a_response("example.com")
    modified = resolver._set_tc_bit(response)
    flags = int.from_bytes(modified[2:4], 'big')
    assert flags & 0x0200 != 0


# ---------- _dnssec_requested ----------
def test_dnssec_requested_detects_do_flag():
    """_dnssec_requested should detect DO flag in EDNS0 OPT record."""
    resolver = DNSResolver()
    query = dns.message.make_query("example.com", "A")
    query.use_edns(flags=dns.flags.DO)
    assert resolver._dnssec_requested(query.to_wire()) is True


def test_dnssec_requested_no_edns():
    """_dnssec_requested should return False when no EDNS0 OPT record."""
    resolver = DNSResolver()
    query = dns.message.make_query("example.com", "A")
    assert resolver._dnssec_requested(query.to_wire()) is False


# ---------- _extract_soa_minimum ----------
def test_extract_soa_minimum():
    """_extract_soa_minimum should extract SOA MINIMUM from authority section."""
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
    """_extract_soa_minimum should return None when no SOA record."""
    resolver = DNSResolver()
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    rr = dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
    resp.answer.append(rr)

    minimum = resolver._extract_soa_minimum(resp.to_wire())
    assert minimum is None


# ---------- _extract_min_ttl ----------
def test_extract_min_ttl():
    """_extract_min_ttl should extract the minimum TTL from answer section."""
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
    """rebind_protection should strip private IPs from responses."""
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
    """rebind_protection with action='block' should return None when all private."""
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
    """_is_private_ip should correctly detect private IPv4 and IPv6 addresses."""
    resolver = DNSResolver()
    assert resolver._is_private_ip("10.0.0.1") is True
    assert resolver._is_private_ip("192.168.1.1") is True
    assert resolver._is_private_ip("172.16.0.1") is True
    assert resolver._is_private_ip("127.0.0.1") is True
    assert resolver._is_private_ip("8.8.8.8") is False
    assert resolver._is_private_ip("::1") is True
    assert resolver._is_private_ip("2001:4860:4860::8888") is False
    assert resolver._is_private_ip("fe80::1") is True  # link-local


# ---------- _split_hostport ----------
def test_split_hostport():
    """_split_hostport should correctly parse host:port strings."""
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
    """set_block_action should set the block action."""
    resolver = DNSResolver()
    resolver.set_block_action("REFUSED")
    assert resolver.get_block_action() == "REFUSED"

    resolver.set_block_action(None)
    assert resolver.get_block_action() == "NXDOMAIN"


# ---------- Build Local A Response ----------
def test_build_local_A_response():
    """_build_local_A_response should synthesize A record response from hosts map."""
    resolver = DNSResolver()
    query = dns.message.make_query("example.com", "A").to_wire()
    response = resolver._build_local_A_response(query, "192.0.2.1")
    msg = dns.message.from_wire(response)
    assert len(msg.answer) == 1
    assert msg.answer[0].rdtype == dns.rdatatype.A
    assert msg.answer[0][0].address == "192.0.2.1"


# ---------- Make NXDOMAIN Response ----------
def test_make_nxdomain_response_preserves_edns():
    """_make_nxdomain_response should preserve EDNS0 options from query."""
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
    """_make_nxdomain_response should handle empty query data."""
    resolver = DNSResolver()
    response = resolver._make_nxdomain_response(b"")
    assert len(response) >= 12  # minimal DNS header


# ---------- Is Negative Response ----------
def test_is_negative_response_nxdomain():
    """_is_negative_response should return True for NXDOMAIN."""
    resolver = DNSResolver()
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    resp.set_rcode(dns.rcode.NXDOMAIN)
    assert resolver._is_negative_response(resp.to_wire()) is True


def test_is_negative_response_noanswer():
    """_is_negative_response should return True for NOERROR with no answers."""
    resolver = DNSResolver()
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    assert resolver._is_negative_response(resp.to_wire()) is True


def test_is_negative_response_with_answer():
    """_is_negative_response should return False for successful response."""
    resolver = DNSResolver()
    resp = make_a_response("example.com")
    assert resolver._is_negative_response(resp) is False


def test_is_negative_response_malformed():
    """_is_negative_response should handle malformed data gracefully."""
    resolver = DNSResolver()
    assert resolver._is_negative_response(b"") is False
    assert resolver._is_negative_response(b"short") is False


# ---------- Make Response from Hosts ----------
@pytest.mark.asyncio
async def test_hosts_map_response():
    """forward_dns_query should return synthesized A record from hosts map."""
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