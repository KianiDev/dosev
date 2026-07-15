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
    """A simple mock DNS server that responds to queries on both UDP and TCP on different ports."""
    def __init__(self, response_func=None, delay=0, tcp_response_func=None):
        self.response_func = response_func or self.default_response
        self.tcp_response_func = tcp_response_func
        self.delay = delay
        self.udp_transport = None
        self.tcp_server = None
        self.udp_port = 0
        self.tcp_port = 0
        self.queries_received = []

    def default_response(self, data, addr):
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
            self.server.udp_transport = transport

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
            if response and self.server.udp_transport:
                self.server.udp_transport.sendto(response, addr)

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
                if self.server.tcp_response_func is not None:
                    response = self.server.tcp_response_func(query, None)
                else:
                    response = self.server.response_func(query, None)
                if response:
                    self.transport.write(len(response).to_bytes(2, 'big') + response)

    async def start(self, host='127.0.0.1'):
        loop = asyncio.get_running_loop()

        # UDP on a random port
        udp_transport, udp_protocol = await loop.create_datagram_endpoint(
            lambda: self.UDPProtocol(self),
            local_addr=(host, 0)
        )
        self.udp_port = udp_transport.get_extra_info('socket').getsockname()[1]

        # TCP on a different random port (avoids Windows permission issues with same port)
        tcp_server = await loop.create_server(
            lambda: self.TCPProtocol(self),
            host=host, port=0
        )
        self.tcp_port = tcp_server.sockets[0].getsockname()[1]
        self.tcp_server = tcp_server
        self.udp_transport = udp_transport
        return self

    async def stop(self):
        if self.udp_transport:
            self.udp_transport.close()
        if self.tcp_server:
            self.tcp_server.close()
            await self.tcp_server.wait_closed()


@pytest.fixture
async def mock_dns_server():
    server = MockDNSServer()
    await server.start()
    yield server
    await server.stop()


@pytest.mark.asyncio
async def test_integration_udp_forward(mock_dns_server):
    resolver = DNSResolver(
        upstreams=[{
            "address": "127.0.0.1",
            "protocol": "udp",
            "port": mock_dns_server.udp_port,
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

    assert len(mock_dns_server.queries_received) == 1


@pytest.mark.asyncio
async def test_integration_tcp_forward(mock_dns_server):
    resolver = DNSResolver(
        upstreams=[{
            "address": "127.0.0.1",
            "protocol": "tcp",
            "port": mock_dns_server.tcp_port,
            "ip": "127.0.0.1"
        }],
        tcp_timeout=2.0,
    )
    query = dns.message.make_query("example.com", "A").to_wire()
    response = await resolver.forward_dns_query(query)

    msg = dns.message.from_wire(response)
    assert msg.rcode() == dns.rcode.NOERROR
    assert len(msg.answer) == 1

    assert len(mock_dns_server.queries_received) == 1


@pytest.mark.asyncio
async def test_integration_truncation_fallback(mock_dns_server):
    def response_with_tc(data, addr):
        try:
            msg = dns.message.from_wire(data)
            resp = dns.message.make_response(msg)
            resp.flags |= dns.flags.TC
            return resp.to_wire()
        except Exception:
            return b""

    # TCP response function returns normal response
    def tcp_response(data, addr):
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

    # Create a server that returns TC for UDP, normal for TCP
    udp_server = MockDNSServer(response_func=response_with_tc, tcp_response_func=tcp_response)
    await udp_server.start()
    try:
        resolver = DNSResolver(
            upstreams=[{
                "address": "127.0.0.1",
                "protocol": "udp",
                "port": udp_server.udp_port,
                "ip": "127.0.0.1"
            }],
            tcp_fallback_enabled=True,
            udp_timeout=1.0,
            tcp_timeout=2.0,
        )

        query = dns.message.make_query("example.com", "A").to_wire()
        response = await resolver.forward_dns_query(query)

        msg = dns.message.from_wire(response)
        assert msg.rcode() == dns.rcode.NOERROR
        assert len(msg.answer) == 1

    finally:
        await udp_server.stop()


@pytest.mark.asyncio
async def test_integration_nxdomain_caching(mock_dns_server):
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
                "port": server.udp_port,
                "ip": "127.0.0.1"
            }],
            negative_cache_ttl=5,
        )
        query = dns.message.make_query("nonexistent.example", "A").to_wire()

        response = await resolver.forward_dns_query(query)
        msg = dns.message.from_wire(response)
        assert msg.rcode() == dns.rcode.NXDOMAIN
        assert len(server.queries_received) == 1

        response2 = await resolver.forward_dns_query(query)
        msg2 = dns.message.from_wire(response2)
        assert msg2.rcode() == dns.rcode.NXDOMAIN
        assert len(server.queries_received) == 1

    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_integration_parallel_load_balancing(mock_dns_server):
    server1 = MockDNSServer()
    await server1.start()
    server2 = MockDNSServer()
    await server2.start()

    try:
        resolver = DNSResolver(
            upstreams=[
                {"address": "127.0.0.1", "protocol": "udp", "port": server1.udp_port, "ip": "127.0.0.1"},
                {"address": "127.0.0.1", "protocol": "udp", "port": server2.udp_port, "ip": "127.0.0.1"},
            ],
            load_balancing="parallel",
            udp_timeout=2.0,
        )
        query = dns.message.make_query("example.com", "A").to_wire()
        response = await resolver.forward_dns_query(query)

        msg = dns.message.from_wire(response)
        assert msg.rcode() == dns.rcode.NOERROR

        assert len(server1.queries_received) == 1
        assert len(server2.queries_received) == 1

    finally:
        await server1.stop()
        await server2.stop()