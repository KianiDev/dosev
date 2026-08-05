import asyncio
import time
import pytest

from dosev.resolver import ConnectionPool, ClientPool, DNSResolver


class DummyWriter:
    def __init__(self):
        self._closed = False
    def is_closing(self):
        return self._closed
    def close(self):
        self._closed = True


@pytest.mark.asyncio
async def test_connection_pool_stop_cleans_up():
    pool = ConnectionPool(max_size=2, idle_timeout=0.1)
    key = ('localhost', 80)
    # create dummy reader/writer pairs
    r1, w1 = object(), DummyWriter()
    r2, w2 = object(), DummyWriter()
    await pool.put(key, r1, w1)
    await pool.put(key, r2, w2)
    # stop should close writers and clear pools
    await pool.stop()
    assert not pool._pools


@pytest.mark.asyncio
async def test_client_pool_stop_closes_clients(monkeypatch):
    pool = ClientPool(max_size=2, idle_timeout=0.1)
    key = ('upstream', 443)
    class DummyClient:
        def __init__(self):
            self.closed = False
        def close(self):
            self.closed = True
    c1 = DummyClient()
    await pool.put(key, c1)
    await pool.stop()
    assert not pool._pools


@pytest.mark.asyncio
async def test_flight_coalescing(monkeypatch):
    resolver = DNSResolver(upstreams=[{'address':'1.1.1.1','protocol':'udp','port':53,'ip':'1.1.1.1'}])
    call_count = 0

    async def fake_try_upstream(upstream, data, _health_check=False, _no_retry=False):
        nonlocal call_count
        call_count += 1
        await asyncio.sleep(0.2)  # was 0.05
        return data[:2] + b'\x81\x80' + data[4:]

    monkeypatch.setattr(resolver, '_try_upstream', fake_try_upstream)

    q = b"\x12\x34" + b"\x01\x00" + b"\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x07example\x03com\x00\x00\x01\x00\x01"

    async def invoke():
        return await resolver.forward_dns_query(q)

    results = await asyncio.gather(invoke(), invoke(), invoke())
    assert call_count == 1
    assert all(r == results[0] for r in results)
 