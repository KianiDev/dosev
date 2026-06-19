import asyncio
from types import SimpleNamespace

import dns.message
import dns.rcode
import pytest

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
