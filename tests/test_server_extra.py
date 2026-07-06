import asyncio
import importlib.util
import os
import signal
import sys
import types
from typing import Dict, Optional, Any, List
import pytest
from dosev.server import run_server, run_server_sync, reload_resolver, ResolverHolder
from dosev.resolver import DNSResolver


class FakeUDPTransport:
    def close(self):
        pass


class FakeTCPServer:
    def __init__(self):
        self.served = False
        self.closed = False

    async def serve_forever(self):
        self.served = True
        while True:
            await asyncio.sleep(0.1)

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


@pytest.mark.asyncio
async def test_run_server_starts_udp_and_tcp_listeners(monkeypatch):
    called = {}

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

    task = asyncio.create_task(run_server(
        listen_ip="127.0.0.1",
        listen_port=5353,
        upstream_dns="1.1.1.1",
        protocol="udp"
    ))

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
    shutdown_called = False

    class FakeTCPServer:
        async def serve_forever(self):
            await asyncio.sleep(3600)

        def close(self):
            nonlocal shutdown_called
            shutdown_called = True

        async def wait_closed(self):
            pass

    async def fake_start_server(handler, host, port):
        return FakeTCPServer()

    async def fake_create_datagram_endpoint(protocol_factory, local_addr):
        return FakeUDPTransport(), None

    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "create_datagram_endpoint", fake_create_datagram_endpoint)
    monkeypatch.setattr(loop, "add_signal_handler", lambda *args, **kwargs: None)
    monkeypatch.setattr("asyncio.start_server", fake_start_server)
    monkeypatch.setattr("dosev.server._drop_dns_privileges", lambda *args, **kwargs: None)

    task = asyncio.create_task(run_server(
        listen_ip="127.0.0.1",
        listen_port=5353,
        upstream_dns="1.1.1.1",
        protocol="udp"
    ))

    await asyncio.sleep(0.1)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    assert shutdown_called is True


def test_run_server_sync_uses_asyncio_run():
    called = {}

    def fake_asyncio_run(coro):
        called['coro'] = coro

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
    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
    called = {}

    def fake_setgid(gid):
        called['setgid'] = gid

    def fake_setuid(uid):
        called['setuid'] = uid

    def fake_chroot(path):
        called['chroot'] = path

    monkeypatch.setattr(os, "setgid", fake_setgid, raising=False)
    monkeypatch.setattr(os, "setuid", fake_setuid, raising=False)
    monkeypatch.setattr(os, "chroot", fake_chroot, raising=False)

    from dosev.server import _drop_dns_privileges
    _drop_dns_privileges("nobody", "nogroup", "/var/empty")

    assert called == {}


def test_drop_dns_privileges_drops_privs_when_root(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)

    if importlib.util.find_spec("pwd") is None:
        pwd = types.SimpleNamespace()
        monkeypatch.setitem(sys.modules, "pwd", pwd)
    else:
        import pwd

    if importlib.util.find_spec("grp") is None:
        grp = types.SimpleNamespace()
        monkeypatch.setitem(sys.modules, "grp", grp)
    else:
        import grp

    class FakePw:
        pw_gid = 999
        pw_uid = 999

    class FakeGrp:
        gr_gid = 999

    monkeypatch.setattr(pwd, "getpwnam", lambda name: FakePw(), raising=False)
    monkeypatch.setattr(grp, "getgrnam", lambda name: FakeGrp(), raising=False)

    called = {}

    def fake_setgid(gid):
        called['setgid'] = gid

    def fake_setuid(uid):
        called['setuid'] = uid

    def fake_setgroups(groups):
        called['setgroups'] = groups

    def fake_chroot(path):
        called['chroot'] = path

    monkeypatch.setattr(os, "setgid", fake_setgid, raising=False)
    monkeypatch.setattr(os, "setuid", fake_setuid, raising=False)
    monkeypatch.setattr(os, "setgroups", fake_setgroups, raising=False)
    monkeypatch.setattr(os, "chroot", fake_chroot, raising=False)

    from dosev.server import _drop_dns_privileges
    _drop_dns_privileges("nobody", "nogroup", "/var/empty")

    assert called.get('setgid') == 999
    assert called.get('setuid') == 999
    assert called.get('setgroups') == []
    assert called.get('chroot') == '/var/empty'


@pytest.mark.asyncio
async def test_reload_resolver_reloads_blocklists(monkeypatch, tmp_path):
    resolver = DNSResolver("1.1.1.1", protocol="udp")
    holder = ResolverHolder(resolver)

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

    assert resolver.upstream_dns == '9.9.9.9'
    assert resolver.protocol == 'tls'
    assert resolver.verbose is True
    assert resolver.disable_ipv6 is True
    assert resolver.udp_timeout == 3.0
    assert resolver.tcp_timeout == 4.0
    assert resolver.doh_timeout == 6.0
    assert resolver.retries == 3
    assert resolver.dnssec_enabled is True

    assert await resolver.is_blocked('blocked.domain') is True
    assert await resolver.is_blocked('sub.badsuffix') is True
    assert await resolver.is_blocked('allowed.domain') is False
    assert resolver.get_block_action() == 'REFUSED'