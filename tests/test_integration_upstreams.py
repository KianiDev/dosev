import asyncio
import dns.message
import dns.rdatatype
import dns.rcode
import pytest
from dosev.resolver import DNSResolver


def _run(coro):
    return asyncio.run(coro)


def test_forward_dns_query_udp_real_upstream():
    async def _test():
        resolver = DNSResolver(
            upstreams=[{"address": "1.1.1.1", "protocol": "udp", "port": 53, "ip": "1.1.1.1"}],
            udp_timeout=5.0
        )
        query = dns.message.make_query("example.com", "A").to_wire()

        response = await resolver.forward_dns_query(query)
        msg = dns.message.from_wire(response)

        assert msg.rcode() == dns.rcode.NOERROR
        assert msg.answer
        assert any(rr.rdtype == dns.rdatatype.A for rr in msg.answer)

    _run(_test())


def test_forward_dns_query_tcp_real_upstream():
    async def _test():
        resolver = DNSResolver(
            upstreams=[{"address": "8.8.8.8", "protocol": "tcp", "port": 53, "ip": "8.8.8.8"}],
            tcp_timeout=5.0
        )
        query = dns.message.make_query("example.com", "A").to_wire()

        response = await resolver.forward_dns_query(query)
        msg = dns.message.from_wire(response)

        assert msg.rcode() == dns.rcode.NOERROR
        assert msg.answer
        assert any(rr.rdtype == dns.rdatatype.A for rr in msg.answer)

    _run(_test())


try:
    import httpx  # noqa: F401
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False


@pytest.mark.skipif(
    not HTTPX_AVAILABLE,
    reason="Requires httpx for DoH tests"
)
def test_forward_dns_query_https_real_upstream():
    async def _test():
        resolver = DNSResolver(
            upstreams=[{
                "address": "cloudflare-dns.com",
                "protocol": "https",
                "port": 443,
                "hostname": "cloudflare-dns.com",
                "path": "/dns-query",
                "doh_version": "1.1",
            }],
            doh_timeout=10.0
        )
        query = dns.message.make_query("example.com", "A").to_wire()

        response = await resolver.forward_dns_query(query)
        msg = dns.message.from_wire(response)

        assert msg.rcode() == dns.rcode.NOERROR
        assert msg.answer
        assert any(rr.rdtype == dns.rdatatype.A for rr in msg.answer)

    _run(_test())