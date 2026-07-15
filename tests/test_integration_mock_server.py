"""
Integration tests using a mock DNS server to test full query flow.
"""

import asyncio
import pytest
import socket
import struct
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rrset
import dns.rcode

from dosev.resolver import DNSResolver


class MockDNSServer:
    """A simple mock DNS server that responds to queries."""
    def __init__(self, response_func=None, delay=0):
        self.response_func = response_func or self.default_response
        self.delay = delay
        self.transport = None
        self.protocol = None
        self.port = 0
        self.queries_received = []
        self._started = asyncio.Event()

    def default_response(self, data, addr):
        """Default response: echo back with an answer."""
        try:
            msg = dns.message.from_wire(data)
            resp = dns.message.make_response(msg)
            if msg.question:
                q = msg.question[0]
                rr = dns.rrset.from_text(str(q.name), 60, dns.rdataclass.IN, q.rdtype, "192.0.2.1")
                resp.answer.append(rr)
            return resp.to_wire()
        except Exception:
            return b""

    class UDPProtocol(asyncio.DatagramProtocol):
        def __init__(self, server):
            self.server = server

        def connection_made(self, transport):
            self.server.transport = transport

        def datagram_received(self, data, addr):
            self.server.queries_received.append((data, addr))
            if self.server.delay:
                asyncio.get_running_loop().call_later(
                    self.server.delay,
                    lambda: self.send_response(data, addr)
                )
            else:
                self.send_response(data, addr)

        def send_response(self, data, addr):
            response = self.server.response_func(data, addr)
            if response and self.server.transport:
                self.server.transport.sendto(response, addr)

    class TCPProtocol(asyncio.Protocol):
        def __init__(self, server):
            self.server = server
            self.transport = None
            self.buffer = b""

        def connection_made(self, transport):
            self.transport = transport

        def data_received(self, data):
            self.buffer += data
            while len(self.buffer) >= 2:
                length = int.from_bytes(self.buffer[:2], 'big')
                if len(self.buffer) < length + 2:
                    break
                query = self.buffer[2:2+length]
                self.buffer = self.buffer[2+length:]
                self.server.queries_received.append((query, self.transport.get_extra_info('peername')))
                response = self.server.response_func(query, None)
                if response:
                    self.transport.write(len(response).to_bytes(2, 'big') + response)

    async def start(self, host='127.0.0.1', port=0):
        loop = asyncio.get_running_loop()

        # UDP
        udp_transport, udp_protocol = await loop.create_datagram_endpoint(
            lambda: self.UDPProtocol(self),
            local_addr=(host, port)
        )
        udp_port = udp_transport.get_extra_info('socket').getsockname()[1]

        # TCP
        tcp_server = await loop.create_server(
            lambda: self.TCPProtocol(self),
            host=host, port=0
        )
        tcp_port = tcp_server.sockets[0].getsockname()[1]

        self.port = udp_port  # use UDP port as primary
        self.udp_transport = udp_transport
        self.tcp_server = tcp_server
        self._started.set()
        return self.port

    async def stop(self):
        if hasattr(self, 'udp_transport'):
            self.udp_transport.close()
        if hasattr(self, 'tcp_server'):
            self.tcp_server.close()
            await self.tcp_server.wait_closed()


@pytest.fixture
async def mock_dns_server():
    server = MockDNSServer()
    port = await server.start()
    yield server
    await server.stop()


@pytest.mark.asyncio
async def test_integration_udp_forward(mock_dns_server):
    """Test UDP forward through mock server."""
    resolver = DNSResolver(
        upstreams=[{
            "address": "127.0.0.1",
            "protocol": "udp",
            "port": mock_dns_server.port,
            "ip": "127.0.0.1"
        }],
        udp_timeout=2.0,
    )
    query = dns.message.make_query("example.com", "A").to_wire()
    response = await resolver.forward_dns_query(query)

    msg = dns.message.from_wire(response)
    assert msg.rcode() == dns.rcode.NOERROR
    assert len(msg.answer) == 1
    assert msg.answer[0].rdtype == dns.rdatatype.A

    # Check server received the query
    assert len(mock_dns_server.queries_received) == 1


@pytest.mark.asyncio
async def test_integration_tcp_forward(mock_dns_server):
    """Test TCP forward through mock server."""
    resolver = DNSResolver(
        upstreams=[{
            "address": "127.0.0.1",
            "protocol": "tcp",
            "port": mock_dns_server.port,
            "ip": "127.0.0.1"
        }],
        tcp_timeout=2.0,
    )
    query = dns.message.make_query("example.com", "A").to_wire()
    response = await resolver.forward_dns_query(query)

    msg = dns.message.from_wire(response)
    assert msg.rcode() == dns.rcode.NOERROR
    assert len(msg.answer) == 1

    # Server should have received the TCP query
    assert len(mock_dns_server.queries_received) == 1


@pytest.mark.asyncio
async def test_integration_truncation_fallback(mock_dns_server):
    """Test TCP fallback when UDP response has TC bit set."""
    def response_with_tc(data, addr):
        try:
            msg = dns.message.from_wire(data)
            resp = dns.message.make_response(msg)
            resp.flags |= dns.flags.TC  # Set truncation bit
            return resp.to_wire()
        except Exception:
            return b""

    # Create a server that always returns TC for UDP
    udp_server = MockDNSServer(response_func=response_with_tc)
    await udp_server.start()
    try:
        resolver = DNSResolver(
            upstreams=[{
                "address": "127.0.0.1",
                "protocol": "udp",
                "port": udp_server.port,
                "ip": "127.0.0.1"
            }],
            tcp_fallback_enabled=True,
            udp_timeout=1.0,
            tcp_timeout=2.0,
        )

        # We need a TCP server that returns a proper response
        # The mock server already has TCP support

        query = dns.message.make_query("example.com", "A").to_wire()
        response = await resolver.forward_dns_query(query)

        # Should get the proper response from TCP fallback
        msg = dns.message.from_wire(response)
        assert msg.rcode() == dns.rcode.NOERROR
        assert len(msg.answer) == 1

    finally:
        await udp_server.stop()


@pytest.mark.asyncio
async def test_integration_nxdomain_caching(mock_dns_server):
    """Test that NXDOMAIN responses are cached."""
    def nxdomain_response(data, addr):
        try:
            msg = dns.message.from_wire(data)
            resp = dns.message.make_response(msg)
            resp.set_rcode(dns.rcode.NXDOMAIN)
            return resp.to_wire()
        except Exception:
            return b""

    server = MockDNSServer(response_func=nxdomain_response)
    await server.start()
    try:
        resolver = DNSResolver(
            upstreams=[{
                "address": "127.0.0.1",
                "protocol": "udp",
                "port": server.port,
                "ip": "127.0.0.1"
            }],
            negative_cache_ttl=5,
        )
        query = dns.message.make_query("nonexistent.example", "A").to_wire()

        # First query should go to server
        response = await resolver.forward_dns_query(query)
        msg = dns.message.from_wire(response)
        assert msg.rcode() == dns.rcode.NXDOMAIN
        assert len(server.queries_received) == 1

        # Second query should be cached (no new query to server)
        response2 = await resolver.forward_dns_query(query)
        msg2 = dns.message.from_wire(response2)
        assert msg2.rcode() == dns.rcode.NXDOMAIN
        assert len(server.queries_received) == 1

    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_integration_parallel_load_balancing(mock_dns_server):
    """Test parallel load balancing with multiple upstreams."""
    # Start two servers
    server1 = MockDNSServer()
    await server1.start()
    server2 = MockDNSServer()
    await server2.start()

    try:
        resolver = DNSResolver(
            upstreams=[
                {"address": "127.0.0.1", "protocol": "udp", "port": server1.port, "ip": "127.0.0.1"},
                {"address": "127.0.0.1", "protocol": "udp", "port": server2.port, "ip": "127.0.0.1"},
            ],
            load_balancing="parallel",
            udp_timeout=2.0,
        )
        query = dns.message.make_query("example.com", "A").to_wire()
        response = await resolver.forward_dns_query(query)

        msg = dns.message.from_wire(response)
        assert msg.rcode() == dns.rcode.NOERROR

        # Both servers should have received the query (parallel)
        assert len(server1.queries_received) == 1
        assert len(server2.queries_received) == 1

    finally:
        await server1.stop()
        await server2.stop()