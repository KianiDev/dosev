"""
Tests for upstream selection strategies.
"""

import asyncio
import random
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

import dns.message
from dosev.resolver import DNSResolver


@pytest.fixture
def resolver():
    return DNSResolver(
        upstreams=[
            {"address": "upstream1", "protocol": "udp", "port": 53, "ip": "1.1.1.1"},
            {"address": "upstream2", "protocol": "udp", "port": 53, "ip": "8.8.8.8"},
            {"address": "upstream3", "protocol": "udp", "port": 53, "ip": "9.9.9.9"},
        ],
        load_balancing="failover",  # will be overridden in tests
    )


@pytest.mark.asyncio
async def test_load_balancing_failover(resolver):
    """Failover: try upstreams in order until one succeeds."""
    # Mock _try_upstream to fail on first, succeed on second
    call_order = []
    async def fake_try_upstream(upstream, data):
        call_order.append(upstream["address"])
        if upstream["address"] == "upstream1":
            raise Exception("fail")
        return b"success"
    resolver._try_upstream = fake_try_upstream

    query = dns.message.make_query("example.com", "A").to_wire()
    resolver.load_balancing = "failover"
    response = await resolver.forward_dns_query(query)
    assert response == b"success"
    assert call_order == ["upstream1", "upstream2"]


@pytest.mark.asyncio
async def test_load_balancing_parallel(resolver):
    """Parallel: query all upstreams, return first success."""
    # Mock _try_upstream to succeed on second call after delay
    call_order = []
    async def fake_try_upstream(upstream, data):
        call_order.append(upstream["address"])
        await asyncio.sleep(0.05)  # simulate work
        if upstream["address"] == "upstream1":
            return b"success1"
        return b"success2"
    resolver._try_upstream = fake_try_upstream

    query = dns.message.make_query("example.com", "A").to_wire()
    resolver.load_balancing = "parallel"
    # We need to ensure that the first response is returned (should be upstream1)
    response = await resolver.forward_dns_query(query)
    assert response == b"success1"
    # All upstreams should have been called
    assert set(call_order) == {"upstream1", "upstream2", "upstream3"}


@pytest.mark.asyncio
async def test_load_balancing_parallel_all_fail(resolver):
    """Parallel: if all fail, raise the last exception."""
    async def fake_try_upstream(upstream, data):
        raise Exception(f"fail {upstream['address']}")
    resolver._try_upstream = fake_try_upstream

    query = dns.message.make_query("example.com", "A").to_wire()
    resolver.load_balancing = "parallel"
    with pytest.raises(Exception) as exc:
        await resolver.forward_dns_query(query)
    assert "fail" in str(exc.value)


@pytest.mark.asyncio
async def test_load_balancing_random(resolver):
    """Random: pick a random upstream for each query."""
    # Monkeypatch random.choice to return a deterministic upstream
    original_choice = random.choice
    try:
        choices = ["upstream1", "upstream2", "upstream3"]
        def mock_choice(seq):
            return choices.pop(0)
        random.choice = mock_choice

        resolver.load_balancing = "random"
        # Mock _try_upstream to record which upstream was used
        used = []
        async def fake_try_upstream(upstream, data):
            used.append(upstream["address"])
            return b"success"
        resolver._try_upstream = fake_try_upstream

        query = dns.message.make_query("example.com", "A").to_wire()
        response = await resolver.forward_dns_query(query)
        assert response == b"success"
        assert used == ["upstream1"]

        # Second call should pick upstream2
        response = await resolver.forward_dns_query(query)
        assert used == ["upstream1", "upstream2"]
    finally:
        random.choice = original_choice


@pytest.mark.asyncio
async def test_load_balancing_roundrobin(resolver):
    """Round‑robin: cycle through upstreams."""
    resolver.load_balancing = "roundrobin"
    used = []
    async def fake_try_upstream(upstream, data):
        used.append(upstream["address"])
        return b"success"
    resolver._try_upstream = fake_try_upstream

    query = dns.message.make_query("example.com", "A").to_wire()

    # First call -> upstream1
    response = await resolver.forward_dns_query(query)
    assert response == b"success"
    assert used == ["upstream1"]

    # Second call -> upstream2
    response = await resolver.forward_dns_query(query)
    assert used == ["upstream1", "upstream2"]

    # Third call -> upstream3
    response = await resolver.forward_dns_query(query)
    assert used == ["upstream1", "upstream2", "upstream3"]

    # Fourth call -> upstream1 again
    response = await resolver.forward_dns_query(query)
    assert used == ["upstream1", "upstream2", "upstream3", "upstream1"]