import asyncio
import os
from types import SimpleNamespace

import dns.message
import dns.rcode
import pytest

from dosev.resolver import DNSResolver
from dosev.server import ResolverHolder, UDPResolverProtocol, _tcp_handler, reload_resolver, _drop_dns_privileges, run_server, run_server_sync


class FakeTransport:
    def __init__(self):
        self.sent = []

    def sendto(self, data, addr):
        self.sent.append((data, addr))

    def close(self):
        pass


class FakeWriter:
    def __init__(self):
        self.written = bytearray()
        self.closed = False
        self._closed = False

    def write(self, data):
        self.written.extend(data)

    async def drain(self):
        return None

    def close(self):
        self.closed = True

    async def wait_closed(self):
        self._closed = True

    def get_extra_info(self, key):
        if key == "peername":
            return ("127.0.0.1", 12345)
        return None


class FakeReader:
    def __init__(self, payload: bytes):
        self._payload = payload
        self._pos = 0

    async def readexactly(self, n):
        chunk = self._payload[self._pos:self._pos + n]
        self._pos += n
        return chunk


@pytest.mark.asyncio
async def test_udp_protocol_handles_blocked_and_forwarded_queries():
    class FakeResolver:
        def __init__(self):
            self.rate_limiter = None
            self.disable_ipv6 = False
            self._block_action = "NXDOMAIN"
            self.forwarded = []

        async def forward_dns_query(self, data):
            self.forwarded.append(data)
            response = dns.message.make_response(dns.message.from_wire(data))
            return response.to_wire()

        def is_blocked(self, qname):
            return qname == "blocked.example"

        def get_block_action(self):
            return "NXDOMAIN"

        def build_block_response(self, data, action=None):
            response = dns.message.make_response(dns.message.from_wire(data))
            response.set_rcode(dns.rcode.NXDOMAIN)
            return response.to_wire()

        def log_dns_event(self, *args, **kwargs):
            return None

    resolver = FakeResolver()
    transport = FakeTransport()
    protocol = UDPResolverProtocol(ResolverHolder(resolver))
    protocol.transport = transport

    query = dns.message.make_query("blocked.example", "A")
    await protocol._handle(query.to_wire(), ("127.0.0.1", 53))
    assert transport.sent

    query = dns.message.make_query("good.example", "A")
    await protocol._handle(query.to_wire(), ("127.0.0.1", 53))
    assert len(resolver.forwarded) == 1


@pytest.mark.asyncio
async def test_tcp_handler_sends_response(monkeypatch):
    class FakeResolver:
        def __init__(self):
            self.rate_limiter = None
            self.disable_ipv6 = False
            self.forwarded = []

        async def forward_dns_query(self, data):
            self.forwarded.append(data)
            response = dns.message.make_response(dns.message.from_wire(data))
            return response.to_wire()

        def is_blocked(self, qname):
            return False

        def get_block_action(self):
            return "NXDOMAIN"

        def build_block_response(self, data, action=None):
            response = dns.message.make_response(dns.message.from_wire(data))
            response.set_rcode(dns.rcode.NXDOMAIN)
            return response.to_wire()

        def log_dns_event(self, *args, **kwargs):
            return None

    query = dns.message.make_query("example.com", "A")
    payload = query.to_wire()
    reader = FakeReader(len(payload).to_bytes(2, "big") + payload)
    writer = FakeWriter()
    resolver = FakeResolver()
    await _tcp_handler(reader, writer, ResolverHolder(resolver))

    assert resolver.forwarded
    assert writer.written


@pytest.mark.asyncio
async def test_reload_resolver_fetches_and_reloads_blocklists(monkeypatch):
    class FakeResolver:
        def __init__(self):
            self.upstream_dns = "1.1.1.1"
            self.protocol = "udp"
            self._config_lock = asyncio.Lock()

        async def update_config(self, **kwargs):
            self.updated = kwargs

        def set_block_action(self, action):
            self.block_action = action

        def load_blocklists_from_dir(self, directory):
            return ({"example.com"}, {"bad.com"}, {"hosts.example": ("127.0.0.1",)})

        def set_blocklist(self, domains):
            self.domains = domains

        def set_hosts_map(self, hosts_map):
            self.hosts_map = hosts_map

    resolver = FakeResolver()
    called = {}

    async def fake_fetch(urls, destination_dir=None):
        called["fetch"] = True

    monkeypatch.setattr("dosev.server.fetch_blocklists", fake_fetch)

    await reload_resolver(
        ResolverHolder(resolver),
        {
            "upstream_dns": "8.8.8.8",
            "protocol": "tcp",
            "upstreams": [],
            "blocklists": {}
        },
        resolver,
        blocklists={
            "action": "REFUSED",
            "urls": ["https://example.com/list.txt"],
            "local_blocklist_dir": "tmp-blocklists",
        },
    )

    assert resolver.block_action == "REFUSED"
    assert called.get("fetch") is True
    assert resolver.domains
    assert resolver.hosts_map


def test_drop_dns_privileges_noop_when_not_root(monkeypatch):
    monkeypatch.setattr("dosev.server.os.geteuid", lambda: 1000)
    _drop_dns_privileges("nobody")


@pytest.mark.asyncio
async def test_run_server_calls_cleanup_and_shutdown(monkeypatch):
    class FakeResolver:
        def __init__(self):
            self.started = False
            self.stopped = False

        async def start_pool_cleanups(self):
            self.started = True

        async def stop_pool_cleanups(self):
            self.stopped = True

    fake_resolver = FakeResolver()

    class FakeServer:
        def __init__(self):
            self.closed = False

        async def wait_closed(self):
            self.closed = True

        def close(self):
            self.closed = True

        async def serve_forever(self):
            return None

    fake_server = FakeServer()

    async def fake_wait(coros, return_when):
        return ([], [])

    class FakeTransport:
        def close(self):
            self.closed = True

    fake_transport = FakeTransport()

    monkeypatch.setattr("dosev.server.DNSResolver", lambda **kwargs: fake_resolver)
    async def fake_start_server(*args, **kwargs):
        return fake_server

    monkeypatch.setattr("dosev.server.asyncio.start_server", fake_start_server)
    monkeypatch.setattr("dosev.server.asyncio.wait", fake_wait)

    class FakeLoop:
        def __init__(self):
            self.transport = fake_transport

        async def create_datagram_endpoint(self, *args, **kwargs):
            return self.transport, None

        def add_signal_handler(self, *args, **kwargs):
            return None

        def create_task(self, coro):
            return None

    monkeypatch.setattr("dosev.server.asyncio.get_running_loop", lambda: FakeLoop())

    await run_server(
        listen_ip="127.0.0.1",
        listen_port=5353,
        upstream_dns="1.1.1.1",
        protocol="udp",
    )

    assert fake_resolver.started is True


def test_run_server_sync_uses_asyncio_run(monkeypatch):
    called = {}

    def fake_run(coro):
        called["ran"] = True
        return None

    monkeypatch.setattr("dosev.server.asyncio.run", fake_run)
    run_server_sync("127.0.0.1", 5353, "1.1.1.1", "udp")
    assert called["ran"] is True
@pytest.mark.asyncio
async def test_run_server_starts_udp_and_tcp_listeners(monkeypatch):
    """Test that run_server creates UDP and TCP listeners."""
    called = {}
    
    class FakeUDPTransport:
        def close(self):
            pass
    
    class FakeTCPServer:
        async def serve_forever(self):
            called['served'] = True
        def close(self):
            called['closed'] = True
        async def wait_closed(self):
            pass
    
    async def fake_create_datagram_endpoint(protocol_factory, local_addr):
        called['udp_started'] = True
        return FakeUDPTransport(), None
    
    async def fake_start_server(handler, host, port):
        called['tcp_started'] = True
        return FakeTCPServer()
    
    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "create_datagram_endpoint", fake_create_datagram_endpoint)
    monkeypatch.setattr(loop, "add_signal_handler", lambda *args, **kwargs: None)
    monkeypatch.setattr("asyncio.start_server", fake_start_server)
    monkeypatch.setattr("dosev.server._drop_dns_privileges", lambda *args, **kwargs: None)
    
    # Run server with a short timeout
    task = asyncio.create_task(run_server(
        listen_ip="127.0.0.1",
        listen_port=5353,
        upstream_dns="1.1.1.1",
        protocol="udp"
    ))
    
    # Let it start
    await asyncio.sleep(0.1)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    
    assert called.get('udp_started') is True
    assert called.get('tcp_started') is True

@pytest.mark.asyncio
async def test_run_server_graceful_shutdown_on_signal(monkeypatch):
    """Test that run_server shuts down cleanly when a signal is received."""
    shutdown_called = False
    
    class FakeTCPServer:
        async def serve_forever(self):
            await asyncio.sleep(3600)  # Never returns
        def close(self):
            nonlocal shutdown_called
            shutdown_called = True
        async def wait_closed(self):
            pass
    
    async def fake_start_server(handler, host, port):
        return FakeTCPServer()
    
    class FakeUDPTransport:
        def close(self):
            pass

    async def fake_create_datagram_endpoint(protocol_factory, local_addr):
        return FakeUDPTransport(), None
    
    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "create_datagram_endpoint", fake_create_datagram_endpoint)
    monkeypatch.setattr(loop, "add_signal_handler", lambda *args, **kwargs: None)
    monkeypatch.setattr("asyncio.start_server", fake_start_server)
    monkeypatch.setattr("dosev.server._drop_dns_privileges", lambda *args, **kwargs: None)
    
    # Simulate signal by setting shutdown_event manually
    # We'll test the signal handler path separately
    # This test ensures the finally block runs
    task = asyncio.create_task(run_server(
        listen_ip="127.0.0.1",
        listen_port=5353,
        upstream_dns="1.1.1.1",
        protocol="udp"
    ))
    
    # Wait for startup, then cancel
    await asyncio.sleep(0.1)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    
    assert shutdown_called is True

def test_run_server_sync_wraps_asyncio_run():
    """Test that run_server_sync calls asyncio.run with correct args."""
    called = {}
    
    def fake_asyncio_run(coro):
        called['coro'] = coro
    
    import dosev.server
    original_run = asyncio.run
    asyncio.run = fake_asyncio_run
    
    try:
        run_server_sync(
            listen_ip="1.2.3.4",
            listen_port=9999,
            upstream_dns="8.8.8.8",
            protocol="tls",
            verbose=True
        )
        assert called['coro'] is not None
    finally:
        asyncio.run = original_run
def test_drop_dns_privileges_does_nothing_when_not_root(monkeypatch):
    """Test that _drop_dns_privileges does nothing when not running as root."""
    monkeypatch.setattr(os, "geteuid", lambda: 1000)  # Not root
    called = {}
    
    def fake_setgid(gid):
        called['setgid'] = gid
    def fake_setuid(uid):
        called['setuid'] = uid
    def fake_chroot(path):
        called['chroot'] = path
    
    monkeypatch.setattr(os, "setgid", fake_setgid)
    monkeypatch.setattr(os, "setuid", fake_setuid)
    monkeypatch.setattr(os, "chroot", fake_chroot)
    
    _drop_dns_privileges("nobody", "nogroup", "/var/empty")
    
    # Should not have called any of these
    assert called == {}

def test_drop_dns_privileges_drops_privs_when_root(monkeypatch):
    """Test that _drop_dns_privileges drops privileges when running as root."""
    monkeypatch.setattr(os, "geteuid", lambda: 0)  # Root
    
    import pwd
    import grp
    
    class FakePw:
        pw_gid = 999
        pw_uid = 999
    
    class FakeGrp:
        gr_gid = 999
    
    monkeypatch.setattr(pwd, "getpwnam", lambda name: FakePw())
    monkeypatch.setattr(grp, "getgrnam", lambda name: FakeGrp())
    
    called = {}
    
    def fake_setgid(gid):
        called['setgid'] = gid
    def fake_setuid(uid):
        called['setuid'] = uid
    def fake_setgroups(groups):
        called['setgroups'] = groups
    def fake_chroot(path):
        called['chroot'] = path
    
    monkeypatch.setattr(os, "setgid", fake_setgid)
    monkeypatch.setattr(os, "setuid", fake_setuid)
    monkeypatch.setattr(os, "setgroups", fake_setgroups)
    monkeypatch.setattr(os, "chroot", fake_chroot)
    
    _drop_dns_privileges("nobody", "nogroup", "/var/empty")
    
    assert called.get('setgid') == 999
    assert called.get('setuid') == 999
    assert called.get('setgroups') == []
    assert called.get('chroot') == '/var/empty'
@pytest.mark.asyncio
async def test_reload_resolver_reloads_blocklists(monkeypatch, tmp_path):
    """Test that reload_resolver reloads blocklists when configured."""
    resolver = DNSResolver("1.1.1.1", protocol="udp")
    holder = ResolverHolder(resolver)
    
    # Create a fake blocklist file
    blocklist_dir = tmp_path / "blocklists"
    blocklist_dir.mkdir()
    (blocklist_dir / "test.txt").write_text("blocked.domain\n.badsuffix\n")
    
    blocklists_config = {
        'action': 'REFUSED',
        'urls': [],
        'local_blocklist_dir': str(blocklist_dir),
    }
    
    reload_called = False
    async def fake_fetch_blocklists(urls, destination_dir):
        nonlocal reload_called
        reload_called = True
    
    monkeypatch.setattr("dosev.server.fetch_blocklists", fake_fetch_blocklists)
    
    config = {
        'upstream_dns': '9.9.9.9',
        'protocol': 'tls',
        'verbose': True,
        'disable_ipv6': True,
        'upstream_udp_timeout': 3.0,
        'upstream_tcp_timeout': 4.0,
        'upstream_doh_timeout': 6.0,
        'upstream_retries': 3,
        'dns_pinned_certs': {},
        'dnssec_enabled': True,
        'trust_anchors_file': '',
        'metrics_enabled': False,
        'metrics_port': 8000,
        'rate_limit_rps': 1.0,
        'rate_limit_burst': 2.0,
        'upstreams': [],
        'optimistic_cache_enabled': True,
        'optimistic_stale_max_age': 100,
        'optimistic_stale_response_ttl': 10,
        'dns_rebind_protection': True,
        'dns_rebind_action': 'block',
        'pool_max_size': 10,
        'pool_idle_timeout': 30.0,
        'doh_version': '2',
        'doh_auto_cache_ttl': 2000,
        'bootstrap': {'servers': ['1.1.1.1:53'], 'timeout': 1.0, 'retries': 1},
    }
    
    await reload_resolver(holder, config, resolver, blocklists_config)
    
    # Check that the resolver was updated
    assert resolver.upstream_dns == '9.9.9.9'
    assert resolver.protocol == 'tls'
    assert resolver.verbose is True
    assert resolver.disable_ipv6 is True
    assert resolver.udp_timeout == 3.0
    assert resolver.tcp_timeout == 4.0
    assert resolver.doh_timeout == 6.0
    assert resolver.retries == 3
    assert resolver.dnssec_enabled is True
    
    # Check blocklist was loaded
    assert resolver.is_blocked('blocked.domain') is True
    assert resolver.is_blocked('sub.badsuffix') is True
    assert resolver.is_blocked('allowed.domain') is False
    assert resolver.get_block_action() == 'REFUSED'