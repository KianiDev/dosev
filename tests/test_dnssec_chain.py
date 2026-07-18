# tests/test_dnssec_chain.py
"""
Tests for DNSSEC chain‑of‑trust validation in the DNSResolver.
All external network calls are mocked to ensure reproducibility.
"""

import asyncio
import unittest
from unittest.mock import patch, MagicMock, AsyncMock
import time
import calendar

import dns.message
import dns.rrset
import dns.rdatatype
import dns.rdataclass
import dns.name
import dns.rdtypes.ANY.DNSKEY
import dns.rdtypes.ANY.DS
import dns.rdtypes.ANY.NSEC3

from dosev.resolver import DNSResolver


def make_dnskey_rrset(owner: str, flags: int, protocol: int, algorithm: int, key: bytes) -> dns.rrset.RRset:
    """Helper to create a DNSKEY RRset."""
    rr = dns.rrset.from_text(owner, 3600, "IN", "DNSKEY", f"{flags} {protocol} {algorithm} {key.hex()}")
    return rr


def make_ds_rrset(owner: str, key_tag: int, algorithm: int, digest_type: int, digest: bytes) -> dns.rrset.RRset:
    """Helper to create a DS RRset."""
    ds_text = f"{key_tag} {algorithm} {digest_type} {digest.hex()}"
    return dns.rrset.from_text(owner, 3600, "IN", "DS", ds_text)


class TestDNSSECChain(unittest.IsolatedAsyncioTestCase):
    async def test_chain_validation_valid(self):
        """Test that a valid signed response passes chain validation."""
        resolver = DNSResolver(
            dnssec_enabled=True,
            dnssec_chain_validation=True,
            dnssec_max_validations=10,
            dnssec_max_dnskey_records=5,
            dnssec_validation_timeout=2.0,
            trust_anchors=None,
        )

        ds_rrset = make_ds_rrset(
            "example.com",
            key_tag=12345,
            algorithm=8,
            digest_type=2,
            digest=bytes.fromhex("49aac11d7b6f6446702e54a1607371607a1a41855200fd2ce1cdde32f24e8fb5")
        )
        dnskey_rrset = make_dnskey_rrset(
            "example.com",
            flags=256, protocol=3, algorithm=8,
            key=bytes.fromhex("deadbeef")
        )

        with patch('dns.dnssec.validate_rrsig', return_value=None) as mock_validate:
            # Mocks must match the resolver's internal names (no trailing dot)
            async def fake_lookup(qname, rdtype, dnssec_ok=False):
                if rdtype == dns.rdatatype.DS and qname == "example.com":
                    msg = dns.message.Message()
                    msg.answer.append(ds_rrset)
                    return msg
                if rdtype == dns.rdatatype.DNSKEY and qname == "example.com":
                    msg = dns.message.Message()
                    msg.answer.append(dnskey_rrset)
                    return msg
                return None

            resolver._dnssec_lookup = fake_lookup

            msg = dns.message.make_query("example.com.", dns.rdatatype.A)
            a_rr = dns.rrset.from_text("example.com.", 3600, "IN", "A", "1.2.3.4")
            msg.answer.append(a_rr)
            rrsig_rr = dns.rrset.from_text(
                "example.com.", 3600, "IN", "RRSIG",
                "A 8 2 3600 20350101000000 20300101000000 12345 example.com. deadbeef"
            )
            msg.answer.append(rrsig_rr)
            response_wire = msg.to_wire()

            with patch('time.time', return_value=1893456000):  # 2030-01-01 00:00:00 UTC
                secure, insecure = await resolver._dnssec_validate_chain("example.com", response_wire, dnssec_requested=True)
                self.assertTrue(secure)
                self.assertFalse(insecure)
                mock_validate.assert_called()

    async def test_chain_validation_insecure_delegation_nsec3_optout(self):
        """Test that NSEC3 opt‑out proves an insecure delegation."""
        resolver = DNSResolver(
            dnssec_enabled=True,
            dnssec_chain_validation=True,
            dnssec_max_validations=10,
            dnssec_max_dnskey_records=5,
            dnssec_validation_timeout=2.0,
            trust_anchors=None,
        )

        def fake_hash(name, salt, iterations, algorithm):
            return "aaaaaaaaaaaaaaaa"
        resolver._nsec3_hash = fake_hash

        # Create NSEC3 record with opt‑out and empty bitmap
        nsec3 = dns.rdtypes.ANY.NSEC3.NSEC3(
            rdclass=dns.rdataclass.IN,
            rdtype=dns.rdatatype.NSEC3,
            algorithm=1,
            flags=0x01,
            iterations=0,
            salt=b'',
            next=b'aaaaaaaaaaaaaaaa',
            windows=[(0, b'\x00')]     # empty bitmap: no types (including DS)
        )
        nsec3_rrset = dns.rrset.RRset(dns.name.from_text("aaaaaaaaaaaaaaaa.example.com."), dns.rdataclass.IN, dns.rdatatype.NSEC3)
        nsec3_rrset.ttl = 3600
        nsec3_rrset.add(nsec3)

        async def fake_lookup(qname, rdtype, dnssec_ok=False):
            if rdtype == dns.rdatatype.NSEC3 and qname == ".":
                msg = dns.message.Message()
                msg.authority.append(nsec3_rrset)
                return msg
            return None

        resolver._dnssec_lookup = fake_lookup

        result = await resolver._prove_insecure_delegation("example.com", ".")
        self.assertTrue(result)

    async def test_chain_validation_fails_on_bogus_signature(self):
        """Test that a bogus signature causes validation failure."""
        resolver = DNSResolver(
            dnssec_enabled=True,
            dnssec_chain_validation=True,
            dnssec_max_validations=10,
            dnssec_max_dnskey_records=5,
            dnssec_validation_timeout=2.0,
            trust_anchors=None,
        )

        with patch('dns.dnssec.validate_rrsig', side_effect=dns.dnssec.ValidationFailure("Bogus")):
            async def fake_get_key(zone):
                if zone == "example.com":   # no trailing dot
                    return make_dnskey_rrset("example.com.", 256, 3, 8, b"deadbeef")
                return None
            resolver._get_validated_dnskey = fake_get_key

            msg = dns.message.make_query("example.com.", dns.rdatatype.A)
            a_rr = dns.rrset.from_text("example.com.", 3600, "IN", "A", "1.2.3.4")
            msg.answer.append(a_rr)
            rrsig = dns.rrset.from_text(
                "example.com.", 3600, "IN", "RRSIG",
                "A 8 2 3600 20350101000000 20300101000000 12345 example.com. deadbeef"
            )
            msg.answer.append(rrsig)

            with patch('time.time', return_value=1893456000):
                with self.assertRaises(dns.dnssec.ValidationFailure):
                    await resolver._dnssec_validate_chain("example.com", msg.to_wire(), dnssec_requested=True)

    async def test_chain_validation_limits_keytrap(self):
        """Test that KeyTrap limits (max validations) are enforced."""
        resolver = DNSResolver(
            dnssec_enabled=True,
            dnssec_chain_validation=True,
            dnssec_max_validations=1,
            dnssec_max_dnskey_records=5,
            dnssec_validation_timeout=2.0,
            trust_anchors=None,
        )

        async def fake_get_key(zone):
            return make_dnskey_rrset("example.com.", 256, 3, 8, b"deadbeef")
        resolver._get_validated_dnskey = fake_get_key

        msg = dns.message.make_query("example.com.", dns.rdatatype.A)
        a_rr = dns.rrset.from_text("example.com.", 3600, "IN", "A", "1.2.3.4")
        msg.answer.append(a_rr)
        rrsig_a = dns.rrset.from_text(
            "example.com.", 3600, "IN", "RRSIG",
            "A 8 2 3600 20350101000000 20300101000000 12345 example.com. deadbeef"
        )
        msg.answer.append(rrsig_a)

        mx_rr = dns.rrset.from_text("example.com.", 3600, "IN", "MX", "10 mail.example.com.")
        msg.answer.append(mx_rr)
        rrsig_mx = dns.rrset.from_text(
            "example.com.", 3600, "IN", "RRSIG",
            "MX 8 2 3600 20350101000000 20300101000000 12345 example.com. deadbeef"
        )
        msg.answer.append(rrsig_mx)

        with patch('dns.dnssec.validate_rrsig', return_value=None):
            with patch('time.time', return_value=1893456000):
                secure, insecure = await resolver._dnssec_validate_chain("example.com", msg.to_wire(), dnssec_requested=True)
                self.assertFalse(secure)
                self.assertTrue(insecure)

    async def test_chain_validation_fallback_to_legacy(self):
        """Test that when chain validation is disabled, we fall back to legacy."""
        resolver = DNSResolver(
            dnssec_enabled=True,
            dnssec_chain_validation=False,
            dnssec_max_validations=10,
            dnssec_max_dnskey_records=5,
            dnssec_validation_timeout=2.0,
            trust_anchors=None,
        )

        with patch.object(resolver, '_dnssec_validate_old', new_callable=AsyncMock) as mock_old:
            mock_old.return_value = (True, False)
            await resolver._dnssec_validate("example.com", b"dummy", dnssec_requested=True)
            mock_old.assert_called_once()

    async def test_chain_validation_timeout(self):
        """Test that validation respects the timeout."""
        resolver = DNSResolver(
            dnssec_enabled=True,
            dnssec_chain_validation=True,
            dnssec_max_validations=10,
            dnssec_max_dnskey_records=5,
            dnssec_validation_timeout=0.1,
            trust_anchors=None,
        )

        async def slow_get_key(zone):
            await asyncio.sleep(0.5)
            return make_dnskey_rrset("example.com.", 256, 3, 8, b"deadbeef")
        resolver._get_validated_dnskey = slow_get_key

        msg = dns.message.make_query("example.com.", dns.rdatatype.A)
        a_rr = dns.rrset.from_text("example.com.", 3600, "IN", "A", "1.2.3.4")
        msg.answer.append(a_rr)
        rrsig = dns.rrset.from_text(
            "example.com.", 3600, "IN", "RRSIG",
            "A 8 2 3600 20350101000000 20300101000000 12345 example.com. deadbeef"
        )
        msg.answer.append(rrsig)

        with patch('time.time', return_value=1893456000):
            secure, insecure = await resolver._dnssec_validate_chain("example.com", msg.to_wire(), dnssec_requested=True)
            self.assertFalse(secure)
            self.assertTrue(insecure)  # timeout leads to insecure


if __name__ == "__main__":
    unittest.main()