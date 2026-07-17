# tests/test_pool.py
"""
Tests for connection and client pooling in dosev.resolver.
"""

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from dosev.resolver import ConnectionPool, ClientPool


class TestConnectionPool(unittest.IsolatedAsyncioTestCase):
    async def test_stop_closes_all_connections_and_clears_pool(self):
        """Test that stop() closes all connections and clears the pool."""
        pool = ConnectionPool(max_size=2, idle_timeout=5.0)

        mock_writer1 = MagicMock()
        mock_writer1.is_closing.return_value = False
        mock_writer2 = MagicMock()
        mock_writer2.is_closing.return_value = False

        key1 = ("host1", 53)
        key2 = ("host2", 853)
        await pool.put(key1, MagicMock(), mock_writer1)
        await pool.put(key2, MagicMock(), mock_writer2)

        self.assertEqual(len(pool._pools), 2)

        await pool.start_cleanup()
        self.assertIsNotNone(pool._cleanup_task)

        await pool.stop()

        self.assertIsNone(pool._cleanup_task)
        mock_writer1.close.assert_called_once()
        mock_writer2.close.assert_called_once()
        self.assertEqual(len(pool._pools), 0)

    async def test_stop_handles_closing_writers_gracefully(self):
        """Test that stop() handles exceptions from writer.close()."""
        pool = ConnectionPool(max_size=1)

        mock_writer = MagicMock()
        mock_writer.is_closing.return_value = False
        mock_writer.close.side_effect = Exception("Connection reset")

        key = ("host", 53)
        await pool.put(key, MagicMock(), mock_writer)

        await pool.stop()
        mock_writer.close.assert_called_once()
        self.assertEqual(len(pool._pools), 0)

    async def test_stop_cancels_cleanup_task(self):
        """Test that stop() cancels the background cleanup task."""
        pool = ConnectionPool()
        await pool.start_cleanup()
        task = pool._cleanup_task
        self.assertIsNotNone(task)
        self.assertFalse(task.done())

        await pool.stop()

        self.assertTrue(task.done())
        with self.assertRaises(asyncio.CancelledError):
            task.exception()
        self.assertIsNone(pool._cleanup_task)
        self.assertEqual(len(pool._pools), 0)


class TestClientPool(unittest.IsolatedAsyncioTestCase):
    async def test_stop_closes_all_clients_and_clears_pool(self):
        """Test that stop() closes all clients and clears the pool."""
        pool = ClientPool(max_size=2, idle_timeout=5.0)

        mock_client1 = AsyncMock()
        mock_client1.aclose = AsyncMock()
        mock_client2 = AsyncMock()
        mock_client2.close = MagicMock()

        key1 = ("host1", 443)
        key2 = ("host2", 853)
        await pool.put(key1, mock_client1)
        await pool.put(key2, mock_client2)

        self.assertEqual(len(pool._pools), 2)

        await pool.start_cleanup()
        self.assertIsNotNone(pool._cleanup_task)

        await pool.stop()

        self.assertIsNone(pool._cleanup_task)
        mock_client1.aclose.assert_awaited_once()
        # Some clients may be closed differently; just ensure pool is empty
        self.assertEqual(len(pool._pools), 0)

    async def test_stop_handles_client_close_exceptions(self):
        """Test that stop() handles exceptions from client close methods."""
        pool = ClientPool(max_size=1)

        mock_client = MagicMock()
        mock_client.close.side_effect = Exception("Close failed")

        key = ("host", 443)
        await pool.put(key, mock_client)

        await pool.stop()
        self.assertEqual(len(pool._pools), 0)

    async def test_stop_cancels_cleanup_task(self):
        """Test that stop() cancels the background cleanup task."""
        pool = ClientPool()
        await pool.start_cleanup()
        task = pool._cleanup_task
        self.assertIsNotNone(task)
        self.assertFalse(task.done())

        await pool.stop()

        self.assertTrue(task.done())
        with self.assertRaises(asyncio.CancelledError):
            task.exception()
        self.assertIsNone(pool._cleanup_task)
        self.assertEqual(len(pool._pools), 0)

    async def test_stop_handles_quic_connections(self):
        """Test that stop() correctly handles QUIC-like clients with _quic and _cm."""
        pool = ClientPool()

        mock_quic = MagicMock()
        mock_cm = AsyncMock()
        mock_cm.__aexit__ = AsyncMock()

        mock_client = MagicMock()
        mock_client._quic = mock_quic
        mock_client._cm = mock_cm

        key = ("host", 853)
        await pool.put(key, mock_client)

        await pool.stop()

        mock_quic.close.assert_called_once()
        mock_cm.__aexit__.assert_awaited_once_with(None, None, None)
        self.assertEqual(len(pool._pools), 0)


if __name__ == "__main__":
    unittest.main()