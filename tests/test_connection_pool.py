"""
Tests for ConnectionPool and ClientPool.
"""

import asyncio
import pytest
from unittest.mock import MagicMock, AsyncMock

from dosev.resolver import ConnectionPool, ClientPool


@pytest.mark.asyncio
async def test_connection_pool_get_put():
    pool = ConnectionPool(max_size=2)
    key = ("host", 53)
    reader, writer = MagicMock(), MagicMock()
    writer.is_closing.return_value = False

    await pool.put(key, reader, writer)
    result = await pool.get(key)
    assert result is not None
    r, w = result
    assert r is reader
    assert w is writer


@pytest.mark.asyncio
async def test_connection_pool_max_size():
    pool = ConnectionPool(max_size=1)
    key = ("host", 53)
    writer1, writer2 = MagicMock(), MagicMock()
    writer1.is_closing.return_value = False
    writer2.is_closing.return_value = False

    await pool.put(key, MagicMock(), writer1)
    await pool.put(key, MagicMock(), writer2)
    writer2.close.assert_called_once()


@pytest.mark.asyncio
async def test_connection_pool_closed_connection_dropped():
    pool = ConnectionPool()
    key = ("host", 53)
    reader, writer = MagicMock(), MagicMock()
    writer.is_closing.return_value = True

    await pool.put(key, reader, writer)
    result = await pool.get(key)
    assert result is None


@pytest.mark.asyncio
async def test_connection_pool_cleanup():
    pool = ConnectionPool(max_size=2, idle_timeout=0.1)
    key = ("host", 53)
    reader, writer = MagicMock(), MagicMock()
    writer.is_closing.return_value = False

    await pool.put(key, reader, writer)
    await pool.start_cleanup()
    await asyncio.sleep(0.2)

    result = await pool.get(key)
    assert result is None
    await pool.stop()


@pytest.mark.asyncio
async def test_client_pool_basic():
    pool = ClientPool(max_size=2)
    key = ("host", 443)
    client = MagicMock()

    await pool.put(key, client)
    result = await pool.get(key)
    assert result is client


@pytest.mark.asyncio
async def test_client_pool_close_on_eviction():
    """Pool should close clients when evicted."""
    pool = ClientPool(max_size=1)
    key = ("host", 443)
    client1, client2 = MagicMock(), MagicMock()
    # Give both clients an aclose method (AsyncMock)
    client1.aclose = AsyncMock()
    client2.aclose = AsyncMock()

    await pool.put(key, client1)
    await pool.put(key, client2)
    # client1 should be closed
    client1.aclose.assert_awaited_once()


@pytest.mark.asyncio
async def test_client_pool_cleanup():
    pool = ClientPool(idle_timeout=0.1)
    key = ("host", 443)
    client = MagicMock()
    client.aclose = AsyncMock()

    await pool.put(key, client)
    await pool.start_cleanup()
    await asyncio.sleep(0.2)

    result = await pool.get(key)
    assert result is None
    client.aclose.assert_awaited_once()
    await pool.stop()