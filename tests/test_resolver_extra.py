import asyncio
import socket
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import dns.message
import dns.rdatatype
import dns.rcode
import pytest

from dosev.resolver import AsyncTTLCache, DNSResolver


@pytest.mark.asyncio
async def test_dnssec_validate_passes_when_keyring_present(monkeypatch):
    resolver = DNSResolver("1.1.1.1", protocol="udp", dnssec_enabled=True)

    class FakeRrset:
        def __init__(self, name, rdtype):
            self.name = name
            self.rdtype = rdtype

    class FakeSig:
        def __init__(self, name, covered):
            self.name = name
            self.rdtype = dns.rdatatype.RRSIG
            self.type_covered = covered

        def __iter__(self):
            yield self

    class FakeMsg:
        def __init__(self):
            self.answer = [
                FakeRrset("example.com", dns.rdatatype.A),
                FakeSig("example.com", dns.rdatatype.A),
            ]

    def fake_load():
        resolver._dnssec_raw_anchors = {"example.com": []}

    monkeypatch.setattr(resolver, "_load_trust_anchors", fake_load)
    resolver._dnssec_keyring = object()
    monkeypatch.setattr(dns.message, "from_wire", lambda data: FakeMsg())
    monkeypatch.setattr(dns.dnssec, "validate", lambda rrset, candidate, keyring: None)

    await resolver._dnssec_validate("example.com", b"query")


@pytest.mark.asyncio
async def test_load_trust_anchors_builds_keyring_from_file(tmp_path, monkeypatch):
    resolver = DNSResolver("1.1.1.1", protocol="udp")
    anchor_path = tmp_path / "anchors.txt"
    anchor_path.write_text("example.com. 300 IN DNSKEY 257 3 8 ABCDEF\n", encoding="utf-8")

    class FakeRR:
        def __init__(self):
            self._records = []

        def add(self, record):
            self._records.append(record)

        def to_text(self):
            return "FAKE"

        def __iter__(self):
            return iter(self._records)

    class FakeName:
        def __hash__(self):
            return 1

        def __eq__(self, other):
            return True

    def fake_open(path, mode="r", *args, **kwargs):
        return anchor_path.open(mode, *args, **kwargs)

    monkeypatch.setattr("builtins.open", fake_open)
    monkeypatch.setattr("dosev.resolver.dns.rrset.from_text", lambda *args, **kwargs: FakeRR())
    monkeypatch.setattr("dosev.resolver.dns.name.from_text", lambda name: FakeName())
    monkeypatch.setattr(
        "dosev.resolver.dns.dnssec.make_keyring",
        lambda simple: {"built": True},
        raising=False,
    )

    resolver.trust_anchors = {"file": str(anchor_path)}
    resolver._load_trust_anchors()

    assert resolver._dnssec_raw_anchors is not None
    assert resolver._dnssec_keyring == {"built": True}


@pytest.mark.asyncio
async def test_resolve_upstream_ip_prefers_bootstrap_then_getaddrinfo(monkeypatch):
    resolver = DNSResolver("1.1.1.1", protocol="udp")
    resolver.bootstrap_servers = ["1.1.1.1:53"]

    async def fake_udp_query(ip, port, qname, qtype=1):
        return "203.0.113.10" if qtype == 1 else "2001:db8::1"

    class FakeLoop:
        async def getaddrinfo(self, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('203.0.113.20', 0))]

    async def fake_cache_get(key):
        return None

    async def fake_cache_set(key, value):
        return None

    monkeypatch.setattr(resolver, "_udp_query_a_or_aaaa", fake_udp_query)
    monkeypatch.setattr(resolver, "_cache_get", fake_cache_get)
    monkeypatch.setattr(resolver, "_cache_set", fake_cache_set)
    monkeypatch.setattr(asyncio, "get_running_loop", lambda: FakeLoop())

    result = await resolver._resolve_upstream_ip("example.com")
    assert result == "203.0.113.10"


@pytest.mark.asyncio
async def test_resolve_upstream_ip_falls_back_to_system_resolver(monkeypatch):
    resolver = DNSResolver("1.1.1.1", protocol="udp")
    resolver.bootstrap_servers = []

    class FakeLoop:
        async def getaddrinfo(self, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('198.51.100.9', 0))]

    async def fake_cache_get(key):
        return None

    async def fake_cache_set(key, value):
        return None

    monkeypatch.setattr(asyncio, "get_running_loop", lambda: FakeLoop())
    monkeypatch.setattr(resolver, "_cache_get", fake_cache_get)
    monkeypatch.setattr(resolver, "_cache_set", fake_cache_set)

    result = await resolver._resolve_upstream_ip("example.com")
    assert result == "198.51.100.9"


@pytest.mark.asyncio
async def test_wire_cache_helpers_support_legacy_and_current_formats():
    resolver = DNSResolver("1.1.1.1", protocol="udp", cache_ttl=60)
    key = ("example.com", dns.rdatatype.A, "udp")

    await resolver._wire_cache_set(key, (b"resp", 123.0, b"q", 456.0, False))
    assert await resolver._wire_cache_get(key) == (b"resp", 123.0, b"q", 456.0, False)

    resolver._wire_cache = {key: (b"legacy", 1.0, b"q", 2.0)}  # type: ignore
    legacy = await resolver._wire_cache_get(key)
    assert legacy == (b"legacy", 1.0, b"q", 2.0, False)

    await resolver._wire_cache_delete(key)
    assert await resolver._wire_cache_get(key) is None


@pytest.mark.asyncio
async def test_background_refresh_updates_wire_cache(monkeypatch):
    resolver = DNSResolver(
        "1.1.1.1",
        protocol="udp",
        optimistic_cache_enabled=True,
        cache_ttl=1,
    )
    key = ("example.com", dns.rdatatype.A, "udp")
    query = b"query"

    response = dns.message.make_response(dns.message.make_query("example.com", "A"))
    response.answer = [dns.rrset.from_text("example.com.", 60, "IN", "A", "203.0.113.2")]

    async def fake_try_upstream(upstream, data):
        return response.to_wire()

    monkeypatch.setattr(resolver, "_try_upstream", fake_try_upstream)
    monkeypatch.setattr(resolver, "_dnssec_validate", lambda qname, resp: None)

    await resolver._background_refresh(key, query)
    entry = await resolver._wire_cache_get(key)
    assert entry is not None
    assert entry[0] == response.to_wire()


@pytest.mark.asyncio
async def test_with_retries_raises_last_error_after_all_attempts(monkeypatch):
    resolver = DNSResolver("1.1.1.1", protocol="udp", retries=2)

    calls = {"n": 0}

    async def fake_fn(data):
        calls["n"] += 1
        raise RuntimeError("boom")

    async def fake_sleep(delay):
        return None

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    with pytest.raises(RuntimeError, match="boom"):
        await resolver._with_retries(fake_fn, b"query", timeout=0.1)

    assert calls["n"] == 2


@pytest.mark.asyncio
async def test_apply_rebind_protection_blocks_private_answers(monkeypatch):
    resolver = DNSResolver("1.1.1.1", protocol="udp", rebind_protection_enabled=True, rebind_action="block")
    msg = dns.message.make_response(dns.message.make_query("example.com", "A"))
    msg.answer = [dns.rrset.from_text("example.com.", 60, "IN", "A", "10.0.0.1")]
    response = msg.to_wire()

    monkeypatch.setattr(resolver, "_is_private_ip", lambda ip: True)
    filtered = resolver._apply_rebind_protection(response)
    assert filtered != response


def test_make_nxdomain_and_local_a_responses():
    resolver = DNSResolver("1.1.1.1", protocol="udp")
    query = dns.message.make_query("example.com", "A").to_wire()

    nxd = resolver._make_nxdomain_response(query)
    nxd_msg = dns.message.from_wire(nxd)
    assert nxd_msg.rcode() == dns.rcode.NXDOMAIN

    a_resp = resolver._build_local_A_response(query, "203.0.113.7")
    a_msg = dns.message.from_wire(a_resp)
    assert a_msg.rcode() == dns.rcode.NOERROR
    assert len(a_msg.answer) == 1


def test_is_ipv6_address_detects_ipv6():
    resolver = DNSResolver("1.1.1.1", protocol="udp")
    assert resolver._is_ipv6_address("2001:db8::1") is True
    assert resolver._is_ipv6_address("203.0.113.1") is False
    assert resolver._is_ipv6_address("not-an-ip") is False


@pytest.mark.asyncio
async def test_start_and_stop_pool_cleanups():
    resolver = DNSResolver("1.1.1.1", protocol="udp")
    await resolver.start_pool_cleanups()
    await resolver.stop_pool_cleanups()


@pytest.mark.asyncio
async def test_async_cache_used_when_cachetools_missing(monkeypatch):
    import dosev.resolver as resolver_module

    monkeypatch.setattr(resolver_module, "_HAS_CACHETOOLS", False)
    resolver = resolver_module.DNSResolver("1.1.1.1", protocol="udp")
    assert resolver._cache_is_sync is False
    assert isinstance(resolver._dns_cache, AsyncTTLCache)
@pytest.mark.asyncio
async def test_forward_udp_success(monkeypatch):
    """Test UDP forwarding with a mocked datagram endpoint."""
    resolver = DNSResolver("1.1.1.1", protocol="udp")
    resolver._resolve_upstream_ip = AsyncMock(return_value="1.1.1.1")
    
    # Mock the datagram endpoint creation
    class FakeTransport:
        def __init__(self):
            self.sent = []
        def sendto(self, data):
            self.sent.append(data)
        def close(self):
            pass
    
    async def fake_create_datagram_endpoint(protocol_factory, remote_addr, family):
        transport = FakeTransport()
        protocol = protocol_factory()
        protocol.transport = transport
        # Simulate response
        response = dns.message.make_response(dns.message.make_query("example.com", "A")).to_wire()
        protocol.datagram_received(response, ("1.1.1.1", 53))
        return transport, None

    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "create_datagram_endpoint", fake_create_datagram_endpoint)
    
    data = dns.message.make_query("example.com", "A").to_wire()
    result = await resolver._forward_udp(data, {'address': '1.1.1.1', 'port': 53})
    assert len(result) > 0

@pytest.mark.asyncio
async def test_forward_tcp_success(monkeypatch):
    """Test TCP forwarding with mocked connection."""
    resolver = DNSResolver("1.1.1.1", protocol="tcp")
    resolver._resolve_upstream_ip = AsyncMock(return_value="1.1.1.1")
    
    class FakeReader:
        def __init__(self, data):
            self.data = data
            self.pos = 0
        async def readexactly(self, n):
            chunk = self.data[self.pos:self.pos+n]
            self.pos += n
            return chunk
    
    class FakeWriter:
        def __init__(self):
            self.written = bytearray()
            self.closed = False
        def write(self, data):
            self.written.extend(data)
        async def drain(self):
            pass
        def close(self):
            self.closed = True
        async def wait_closed(self):
            pass
        def is_closing(self):
            return self.closed
    
    data = dns.message.make_query("example.com", "A").to_wire()
    response = dns.message.make_response(dns.message.from_wire(data)).to_wire()
    payload = len(response).to_bytes(2, 'big') + response
    
    fake_reader = FakeReader(payload)
    fake_writer = FakeWriter()
    
    async def fake_open_connection(host, port, **kwargs):
        return fake_reader, fake_writer
    
    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    
    result = await resolver._forward_tcp(data, {'address': '1.1.1.1', 'port': 53})
    assert len(result) > 0
    assert fake_writer.written.startswith(len(data).to_bytes(2, 'big'))

@pytest.mark.asyncio
async def test_forward_https1_success(monkeypatch):
    """Test HTTP/1.1 DoH forwarding."""
    resolver = DNSResolver("1.1.1.1", protocol="https")
    resolver._resolve_upstream_ip = AsyncMock(return_value="1.1.1.1")
    
    data = dns.message.make_query("example.com", "A").to_wire()
    response = dns.message.make_response(dns.message.from_wire(data)).to_wire()
    
    class FakeReader:
        def __init__(self, lines):
            self.lines = lines
            self.pos = 0
        async def readline(self):
            if self.pos >= len(self.lines):
                return b''
            line = self.lines[self.pos]
            self.pos += 1
            return line
        async def readexactly(self, n):
            return response[:n]
        async def readuntil(self, separator):
            return b'\r\n'
    
    class FakeWriter:
        def __init__(self):
            self.written = bytearray()
            self.closed = False
        def write(self, data):
            self.written.extend(data)
        async def drain(self):
            pass
        def close(self):
            self.closed = True
        async def wait_closed(self):
            pass
        def get_extra_info(self, key):
            return None
    
    headers = [
        b"HTTP/1.1 200 OK\r\n",
        b"Content-Type: application/dns-message\r\n",
        f"Content-Length: {len(response)}\r\n".encode(),
        b"\r\n",
    ]
    fake_reader = FakeReader(headers)
    fake_writer = FakeWriter()
    
    async def fake_open_connection(host, port, ssl=None, server_hostname=None):
        return fake_reader, fake_writer
    
    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    
    result = await resolver._forward_https1(data, "example.com", 443, "example.com", "/dns-query")
    assert result == response
    assert b"POST /dns-query HTTP/1.1" in fake_writer.written
    assert b"Host: example.com" in fake_writer.written  
@pytest.mark.asyncio
async def test_wire_cache_stale_served(monkeypatch):
    """Test that stale responses are served when optimistic_cache is enabled."""
    resolver = DNSResolver(
        "1.1.1.1",
        optimistic_cache_enabled=True,
        optimistic_stale_max_age=60,
    )
    key = ("example.com", 1, "udp")
    resp = b"fake_response"
    expiry = time.time() - 10  # expired
    stale_until = time.time() + 50  # still within stale window
    val = (resp, expiry, b"query_data", stale_until, False)
    
    async with resolver._lock:
        await resolver._wire_cache_set(key, val)
    
    # Mock the stale refresh to avoid actual network calls
    refresh_called = False
    async def fake_refresh(k, qd):
        nonlocal refresh_called
        refresh_called = True
    monkeypatch.setattr(resolver, "_maybe_refresh_stale", fake_refresh)
    
    cached = await resolver._wire_cache_get_valid(key)
    assert cached is not None
    assert cached[0] == resp
    assert cached[1] is False
    await asyncio.sleep(0)
    assert refresh_called is True

@pytest.mark.asyncio
async def test_wire_cache_expired_deleted(monkeypatch):
    """Test that expired entries are deleted when optimistic_cache is disabled."""
    resolver = DNSResolver("1.1.1.1", optimistic_cache_enabled=False)
    key = ("example.com", 1, "udp")
    resp = b"fake_response"
    expiry = time.time() - 10  # expired
    stale_until = time.time() - 1  # expired
    val = (resp, expiry, b"query_data", stale_until, False)
    
    async with resolver._lock:
        await resolver._wire_cache_set(key, val)
    
    cached = await resolver._wire_cache_get_valid(key)
    assert cached is None
def test_apply_rebind_protection_strips_private_ips():
    """Test that rebind protection strips private IPs from responses."""
    resolver = DNSResolver("1.1.1.1", rebind_protection_enabled=True, rebind_action="strip")
    
    # Create a response with both public and private IPs
    msg = dns.message.make_response(dns.message.make_query("example.com", "A"))
    msg.answer.append(dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "8.8.8.8"))
    msg.answer.append(dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.168.1.1"))
    
    wire = msg.to_wire()
    result = resolver._apply_rebind_protection(wire)
    result_msg = dns.message.from_wire(result)
    
    # Should only contain the public IP
    ips = [rr.to_text().split()[-1] for rr in result_msg.answer if rr.rdtype == dns.rdatatype.A]
    assert "8.8.8.8" in ips
    assert "192.168.1.1" not in ips

def test_apply_rebind_protection_blocks_when_action_block():
    """Test that rebind protection blocks the response when action='block'."""
    resolver = DNSResolver("1.1.1.1", rebind_protection_enabled=True, rebind_action="block")
    
    # Create a response with only private IPs
    msg = dns.message.make_response(dns.message.make_query("example.com", "A"))
    msg.answer.append(dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.168.1.1"))
    
    wire = msg.to_wire()
    result = resolver._apply_rebind_protection(wire)
    result_msg = dns.message.from_wire(result)
    
    # Should return NXDOMAIN
    assert result_msg.rcode() == dns.rcode.NXDOMAIN
@pytest.mark.asyncio
async def test_with_retries_succeeds_on_second_attempt():
    """Test that _with_retries retries on failure and succeeds."""
    resolver = DNSResolver("1.1.1.1", retries=2)
    attempt = 0
    
    async def fake_fn(data):
        nonlocal attempt
        attempt += 1
        if attempt == 1:
            raise Exception("First attempt fails")
        return b"success"
    
    result = await resolver._with_retries(fake_fn, b"data", timeout=1.0)
    assert result == b"success"
    assert attempt == 2

@pytest.mark.asyncio
async def test_with_retries_fails_all_attempts():
    """Test that _with_retries raises after all attempts fail."""
    resolver = DNSResolver("1.1.1.1", retries=2)
    attempt = 0
    
    async def fake_fn(data):
        nonlocal attempt
        attempt += 1
        raise Exception(f"Attempt {attempt} fails")
    
    with pytest.raises(Exception, match="Attempt 2 fails"):
        await resolver._with_retries(fake_fn, b"data", timeout=1.0)
    assert attempt == 2
@pytest.mark.asyncio
async def test_resolve_upstream_ip_all_fail(monkeypatch):
    """Test that _resolve_upstream_ip raises when all resolution methods fail."""
    resolver = DNSResolver("1.1.1.1", protocol="udp")
    resolver.bootstrap_servers = ["1.1.1.1:53"]
    
    # Mock bootstrap to fail
    async def fake_udp_query(ip, port, qname, qtype=1):
        return None
    monkeypatch.setattr(resolver, "_udp_query_a_or_aaaa", fake_udp_query)
    
    # Mock system resolver to fail
    class FakeLoop:
        async def getaddrinfo(self, *args, **kwargs):
            raise socket.gaierror("No address found")
    
    loop = FakeLoop()
    monkeypatch.setattr(asyncio, "get_running_loop", lambda: loop)
    
    with pytest.raises(Exception, match="Unable to resolve upstream hostname"):
        await resolver._resolve_upstream_ip("nonexistent.example.com")
