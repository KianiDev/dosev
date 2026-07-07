"""
Tests for TCP fallback on truncated UDP responses.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

import dns.message
import dns.rdatatype
from dosev.resolver import DNSResolver


@pytest.fixture
def resolver():
    return DNSResolver(
        upstreams=[
            {"address": "1.1.1.1", "protocol": "udp", "port": 53, "ip": "1.1.1.1"},
        ],
        tcp_fallback_enabled=True,
    )


@pytest.mark.asyncio
async def test_tcp_fallback_on_truncation(resolver):
    """If UDP response has TC bit set, retry over TCP."""
    # Mock _forward_udp to return a truncated response (TC=1)
    truncated_response = b'\x00\x00\x80\x00\x00\x01\x00\x00\x00\x00\x00\x00'  # TC bit set
    # We need to set the TC bit in the flags (byte 2-3). The second byte has bit 2 (0x02) set.
    # So we'll craft a proper response with TC.
    # Better: create a real DNS message with TC set.
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    resp.flags |= dns.flags.TC  # set truncation
    truncated_wire = resp.to_wire()

    # Mock _forward_udp to return that
    async def fake_forward_udp(data, upstream):
        return truncated_wire
    resolver._forward_udp = fake_forward_udp

    # Mock _forward_tcp to return a successful response
    tcp_response = b'success_over_tcp'
    async def fake_forward_tcp(data, upstream):
        return tcp_response
    resolver._forward_tcp = fake_forward_tcp

    query_data = query.to_wire()
    result = await resolver._try_upstream(resolver.upstreams[0], query_data)
    assert result == tcp_response


@pytest.mark.asyncio
async def test_tcp_fallback_disabled(resolver):
    """When tcp_fallback_enabled is False, TC bit does not trigger TCP retry."""
    resolver.tcp_fallback_enabled = False
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    resp.flags |= dns.flags.TC
    truncated_wire = resp.to_wire()

    async def fake_forward_udp(data, upstream):
        return truncated_wire
    resolver._forward_udp = fake_forward_udp

    # Mock _forward_tcp to ensure it's not called
    tcp_called = False
    async def fake_forward_tcp(data, upstream):
        nonlocal tcp_called
        tcp_called = True
        return b'tcp'
    resolver._forward_tcp = fake_forward_tcp

    query_data = query.to_wire()
    result = await resolver._try_upstream(resolver.upstreams[0], query_data)
    # Should return the truncated response as-is
    assert result == truncated_wire
    assert tcp_called is False


@pytest.mark.asyncio
async def test_tcp_fallback_does_not_trigger_on_non_truncated(resolver):
    """If UDP response is not truncated, TCP fallback should not occur."""
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    normal_wire = resp.to_wire()

    async def fake_forward_udp(data, upstream):
        return normal_wire
    resolver._forward_udp = fake_forward_udp

    tcp_called = False
    async def fake_forward_tcp(data, upstream):
        nonlocal tcp_called
        tcp_called = True
        return b'tcp'
    resolver._forward_tcp = fake_forward_tcp

    query_data = query.to_wire()
    result = await resolver._try_upstream(resolver.upstreams[0], query_data)
    assert result == normal_wire
    assert tcp_called is False


@pytest.mark.asyncio
async def test_tcp_fallback_uses_same_upstream_with_tcp_protocol(resolver):
    """When falling back, the upstream dict should be converted to TCP."""
    # We'll inspect the upstream passed to _forward_tcp
    captured_upstream = None
    async def fake_forward_udp(data, upstream):
        # Return truncated
        query = dns.message.from_wire(data)
        resp = dns.message.make_response(query)
        resp.flags |= dns.flags.TC
        return resp.to_wire()

    async def fake_forward_tcp(data, upstream):
        nonlocal captured_upstream
        captured_upstream = upstream
        return b'tcp_response'

    resolver._forward_udp = fake_forward_udp
    resolver._forward_tcp = fake_forward_tcp

    query_data = dns.message.make_query("example.com", "A").to_wire()
    result = await resolver._try_upstream(resolver.upstreams[0], query_data)

    assert result == b'tcp_response'
    assert captured_upstream is not None
    assert captured_upstream['protocol'] == 'tcp'
    assert captured_upstream['address'] == resolver.upstreams[0]['address']
    # Port should be default 53 if not set
    assert captured_upstream.get('port') == 53