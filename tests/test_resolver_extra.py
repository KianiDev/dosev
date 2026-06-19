import asyncio
import socket
from types import SimpleNamespace

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
