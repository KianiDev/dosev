"""
Tests for upstream health checks (circuit breaker).
"""

import asyncio
import time
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

import dns.message
from dosev.resolver import DNSResolver


@pytest.fixture
async def resolver_with_health():
    """Resolver with health checks enabled."""
    health_config = {
        'enabled': True,
        'interval': 1,
        'timeout': 1.0,
        'unhealthy_threshold': 2,
        'healthy_threshold': 1,
        'cooldown': 1,
        'domain': '.',
    }
    resolver = DNSResolver(
        upstreams=[
            {"address": "upstream1", "protocol": "udp", "port": 53, "ip": "1.1.1.1"},
            {"address": "upstream2", "protocol": "udp", "port": 53, "ip": "8.8.8.8"},
        ],
        health_config=health_config,
        load_balancing="failover",
    )
    await resolver.start_background_tasks()
    return resolver


@pytest.mark.asyncio
async def test_health_check_initialization(resolver_with_health):
    """Health state should be initialized when health checks are enabled."""
    await asyncio.sleep(0.1)
    assert resolver_with_health._health_task is not None
    assert not resolver_with_health._health_task.done()


@pytest.mark.asyncio
async def test_health_check_mark_unhealthy(resolver_with_health):
    """After consecutive failures, upstream should be marked unhealthy."""
    async def fake_health_check(upstream):
        return False
    resolver_with_health._do_health_check = fake_health_check

    key = resolver_with_health._get_upstream_key(resolver_with_health.upstreams[0])
    async with resolver_with_health._health_lock:
        resolver_with_health._upstream_health[key] = {
            'healthy': True,
            'failures': 2,
            'successes': 0,
            'last_check': 0,
            'next_retry': 0,
        }

    async with resolver_with_health._health_lock:
        state = resolver_with_health._upstream_health[key]
        state['failures'] = 3
        state['healthy'] = False
        state['next_retry'] = time.time() + 10

    healthy = await resolver_with_health._get_healthy_upstreams(resolver_with_health.upstreams)
    assert len(healthy) == 1
    assert healthy[0]['address'] == 'upstream2'


@pytest.mark.asyncio
async def test_health_check_recovery(resolver_with_health):
    """After successful checks, upstream should become healthy again."""
    key = resolver_with_health._get_upstream_key(resolver_with_health.upstreams[0])
    async with resolver_with_health._health_lock:
        resolver_with_health._upstream_health[key] = {
            'healthy': False,
            'failures': 3,
            'successes': 0,
            'last_check': 0,
            'next_retry': 0,
        }

    async def fake_health_check(upstream):
        return True
    resolver_with_health._do_health_check = fake_health_check

    async with resolver_with_health._health_lock:
        state = resolver_with_health._upstream_health[key]
        state['successes'] = 1
        state['healthy'] = True
        state['failures'] = 0

    healthy = await resolver_with_health._get_healthy_upstreams(resolver_with_health.upstreams)
    assert len(healthy) == 2


@pytest.mark.asyncio
async def test_health_check_all_unhealthy_fallback(resolver_with_health):
    """If all upstreams are unhealthy, fallback to all."""
    for up in resolver_with_health.upstreams:
        key = resolver_with_health._get_upstream_key(up)
        async with resolver_with_health._health_lock:
            resolver_with_health._upstream_health[key] = {
                'healthy': False,
                'failures': 3,
                'successes': 0,
                'last_check': 0,
                'next_retry': time.time() + 10,
            }

    healthy = await resolver_with_health._get_healthy_upstreams(resolver_with_health.upstreams)
    assert len(healthy) == 2
    assert healthy == resolver_with_health.upstreams


@pytest.mark.asyncio
async def test_health_check_disabled(resolver_with_health):
    """When health checks are disabled, all upstreams are used."""
    resolver_with_health._health_enabled = False
    healthy = await resolver_with_health._get_healthy_upstreams(resolver_with_health.upstreams)
    assert healthy == resolver_with_health.upstreams


@pytest.mark.asyncio
async def test_health_check_query_success():
    """Test that _do_health_check returns True on successful query."""
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        health_config={'enabled': True},
    )
    # Update fake to accept _no_retry
    async def fake_try_upstream(upstream, data, _health_check=False, _no_retry=False):
        return b'success'
    resolver._try_upstream = fake_try_upstream

    result = await resolver._do_health_check(resolver.upstreams[0])
    assert result is True


@pytest.mark.asyncio
async def test_health_check_query_failure():
    """Test that _do_health_check returns False on failure."""
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        health_config={'enabled': True},
    )
    async def fake_try_upstream(upstream, data, _health_check=False, _no_retry=False):
        raise Exception("timeout")
    resolver._try_upstream = fake_try_upstream

    result = await resolver._do_health_check(resolver.upstreams[0])
    assert result is False