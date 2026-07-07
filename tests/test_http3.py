"""
Tests for HTTP/3 server support.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

import dns.message
from dosev.server import Http3ServerProtocol
from dosev.resolver import DNSResolver
from dosev.server import ResolverHolder


@pytest.mark.asyncio
async def test_http3_protocol_handles_get_request():
    """Test that Http3ServerProtocol handles GET requests."""
    resolver = DNSResolver(upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}])
    holder = ResolverHolder(resolver)

    quic = MagicMock()
    protocol = Http3ServerProtocol(quic=quic)
    protocol.set_holder(holder)

    send_responses = []
    async def fake_send_response(stream_id, status, body, content_type="text/plain"):
        send_responses.append((status, body, content_type))
    protocol._send_response = fake_send_response

    # Mock the internal HTTP connection to fire events
    from aioquic.h3.events import HeadersReceived, DataReceived
    headers = [
        (b":method", b"GET"),
        (b":path", b"/dns-query?dns=AAAAA"),
        (b":scheme", b"https"),
        (b":authority", b"localhost"),
    ]
    event_headers = HeadersReceived(stream_id=0, headers=headers, stream_ended=False)
    event_data = DataReceived(stream_id=0, data=b"", stream_ended=True)

    # Mock _http.handle_event to return these events
    protocol._http = MagicMock()
    protocol._http.handle_event = MagicMock(return_value=[event_headers, event_data])

    # Trigger the event handling
    protocol.quic_event_received(event_headers)  # this will process headers and call handle_event

    # Wait for the async task to complete
    await asyncio.sleep(0.1)

    assert len(send_responses) == 1
    status, body, content_type = send_responses[0]
    assert status == 200
    assert content_type == "application/dns-message"


@pytest.mark.asyncio
async def test_http3_protocol_handles_post_request():
    resolver = DNSResolver(upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}])
    holder = ResolverHolder(resolver)

    quic = MagicMock()
    protocol = Http3ServerProtocol(quic=quic)
    protocol.set_holder(holder)

    send_responses = []
    async def fake_send_response(stream_id, status, body, content_type="text/plain"):
        send_responses.append((status, body, content_type))
    protocol._send_response = fake_send_response

    import dns.message
    query = dns.message.make_query("example.com", "A").to_wire()
    headers = [
        (b":method", b"POST"),
        (b":path", b"/dns-query"),
        (b":scheme", b"https"),
        (b":authority", b"localhost"),
        (b"content-type", b"application/dns-message"),
    ]

    from aioquic.h3.events import HeadersReceived, DataReceived
    event_headers = HeadersReceived(stream_id=0, headers=headers, stream_ended=False)
    event_data = DataReceived(stream_id=0, data=query, stream_ended=True)

    # Mock _http.handle_event to return these events
    protocol._http = MagicMock()
    protocol._http.handle_event = MagicMock(return_value=[event_headers, event_data])

    protocol.quic_event_received(event_headers)
    await asyncio.sleep(0.1)

    assert len(send_responses) == 1
    status, body, content_type = send_responses[0]
    assert status == 200
    assert content_type == "application/dns-message"