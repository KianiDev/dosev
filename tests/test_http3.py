"""
Tests for HTTP/3 server support.
"""

import asyncio
import base64
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

    # Mock forward_dns_query to return a dummy response
    with patch.object(resolver, "forward_dns_query", new=AsyncMock(return_value=b"dummy_response")):
        quic = MagicMock()
        protocol = Http3ServerProtocol(quic=quic)
        protocol.set_holder(holder)

        # Mock _send_response to capture responses
        send_responses = []
        async def fake_send_response(stream_id, status, body, content_type="text/plain"):
            send_responses.append((status, body, content_type))
        protocol._send_response = fake_send_response

        # Directly call _handle_request with mocked headers and body
        # This bypasses the complex event simulation and tests the logic.
        headers = {
            ":method": "GET",
            ":path": "/dns-query?dns=" + base64.urlsafe_b64encode(
                dns.message.make_query("example.com", "A").to_wire()
            ).decode(),
            ":scheme": "https",
            ":authority": "localhost",
        }
        # We need to set _request_headers and _request_data for the stream
        stream_id = 0
        protocol._request_headers[stream_id] = headers
        protocol._request_data[stream_id] = bytearray()

        await protocol._handle_request(stream_id)

        assert len(send_responses) == 1
        status, body, content_type = send_responses[0]
        assert status == 200
        assert content_type == "application/dns-message"


@pytest.mark.asyncio
async def test_http3_protocol_handles_post_request():
    resolver = DNSResolver(upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}])
    holder = ResolverHolder(resolver)

    with patch.object(resolver, "forward_dns_query", new=AsyncMock(return_value=b"dummy_response")):
        quic = MagicMock()
        protocol = Http3ServerProtocol(quic=quic)
        protocol.set_holder(holder)

        send_responses = []
        async def fake_send_response(stream_id, status, body, content_type="text/plain"):
            send_responses.append((status, body, content_type))
        protocol._send_response = fake_send_response

        query = dns.message.make_query("example.com", "A").to_wire()
        headers = {
            ":method": "POST",
            ":path": "/dns-query",
            ":scheme": "https",
            ":authority": "localhost",
            "content-type": "application/dns-message",
        }
        stream_id = 0
        protocol._request_headers[stream_id] = headers
        protocol._request_data[stream_id] = bytearray(query)

        await protocol._handle_request(stream_id)

        assert len(send_responses) == 1
        status, body, content_type = send_responses[0]
        assert status == 200
        assert content_type == "application/dns-message"