# tests/test_dnssec_chain.py
"""
Tests for DNSSEC chain‑of‑trust validation in the DNSResolver.
All external network calls are mocked to ensure reproducibility.
"""

import asyncio
import unittest
from unittest.mock import patch, MagicMock, AsyncMock
import time

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
            trust_anchors=None,  # uses default root key
        )

        # Mock the internal _dnssec_lookup to return pre‑canned responses
        # For a query to 'example.com', we need to simulate:
        # 1. DS for example.com (from parent)
        # 2. DNSKEY for example.com
        # 3. The actual signed answer for example.com A

        # Create a fake DS for example.com (parent zone is .)
        ds_rrset = make_ds_rrset(
            "example.com",
            key_tag=12345,
            algorithm=8,  # RSA/SHA‑256
            digest_type=2,  # SHA‑256
            digest=bytes.fromhex("49aac11d7b6f6446702e54a1607371607a1a41855200fd2ce1cdde32f24e8fb5")
        )
        # Create a fake DNSKEY for example.com that matches the DS
        # Key tag 12345 would be computed from this key; for simplicity we'll reuse the digest.
        # In a real test we'd generate a key, but we can mock the validation call.
        dnskey_rrset = make_dnskey_rrset(
            "example.com",
            flags=256, protocol=3, algorithm=8,
            key=bytes.fromhex("deadbeef")  # dummy
        )

        # The signed response: an A record with an RRSIG signed by the above key.
        # We need to create a message with an answer section containing an A RRset and its RRSIG.
        # For simplicity, we'll build a minimal message and patch dns.dnssec.validate to always succeed.
        # Because generating valid signatures is complex, we'll mock the validation step.

        # Patch dns.dnssec.validate to always succeed
        with patch('dns.dnssec.validate', return_value=None) as mock_validate:
            # Patch _dnssec_lookup to return our synthetic messages
            async def fake_lookup(qname, rdtype, dnssec_ok=False):
                if rdtype == dns.rdatatype.DS and qname == "example.com.":
                    msg = dns.message.Message()
                    msg.answer.append(ds_rrset)
                    return msg
                if rdtype == dns.rdatatype.DNSKEY and qname == "example.com.":
                    msg = dns.message.Message()
                    msg.answer.append(dnskey_rrset)
                    return msg
                return None

            resolver._dnssec_lookup = fake_lookup

            # Build a response wire that contains an A record with RRSIG
            # We'll create a minimal signed response.
            # Use dnspython to build a message with a dummy signature.
            msg = dns.message.make_query("example.com.", dns.rdatatype.A)
            # Add an answer (A record)
            a_rr = dns.rrset.from_text("example.com.", 3600, "IN", "A", "1.2.3.4")
            msg.answer.append(a_rr)
            # Add RRSIG for that A record
            # We'll create a RRSIG with dummy values; validate() will be mocked anyway.
            rrsig_rr = dns.rrset.from_text(
                "example.com.", 3600, "IN", "RRSIG",
                "A 8 2 3600 20260101000000 20250101000000 12345 example.com. deadbeef"
            )
            msg.answer.append(rrsig_rr)
            response_wire = msg.to_wire()

            secure, insecure = await resolver._dnssec_validate_chain("example.com", response_wire, dnssec_requested=True)
            self.assertTrue(secure)
            self.assertFalse(insecure)
            mock_validate.assert_called()  # validation was attempted

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

        # For zone 'example.com' we want to prove that its parent is insecure via NSEC3 opt‑out.
        # We need to simulate a response from parent (.) that contains NSEC3 records with opt‑out.
        # Build a fake NSEC3 record that covers the hash of "example.com" and has opt‑out flag set,
        # and does NOT have a DS bit in the bitmap.

        # We'll use a dummy NSEC3 RRset.
        # The owner name must be the base32hex hash of the domain, but we can craft it.
        # For simplicity, we'll create a record with a dummy hash that covers the range.
        # The hash of "example.com" with salt "" and iterations 0 is a known value.
        # We'll create a NSEC3 record that covers that hash.

        # For testing, we'll just patch _nsec3_hash to return a known value.
        def fake_hash(name, salt, iterations, algorithm):
            return "aaaaaaaaaaaaaaaa"  # dummy hash

        resolver._nsec3_hash = fake_hash

        # Create NSEC3 record with opt‑out flag and no DS in bitmap.
        nsec3_rr = dns.rrset.from_text(
            "aaaaaaaaaaaaaaaa.example.com.", 3600, "IN", "NSEC3",
            "1 0 0 - aaaaaaaaaaaaaaaa A"
        )
        # The above NSEC3 has flags=0, we need to set opt‑out flag (0x01) manually.
        # We'll create the RR from scratch.
        # Create NSEC3 record with opt‑out flag and no DS in bitmap.
        nsec3 = dns.rdtypes.ANY.NSEC3.NSEC3(
            rdclass=dns.rdataclass.IN,
            rdtype=dns.rdatatype.NSEC3,
            algorithm=1,
            flags=0x01,  # opt‑out
            iterations=0,
            salt=b'',
            next=b'aaaaaaaaaaaaaaaa',  # next hash
            windows=[(0, b'\x00')]     # bitmap: no types (including DS)
        )
        nsec3_rrset = dns.rrset.RRset(dns.name.from_text("aaaaaaaaaaaaaaaa.example.com."), dns.rdataclass.IN, dns.rdatatype.NSEC3)
        nsec3_rrset.ttl = 3600
        nsec3_rrset.add(nsec3)

        # Patch _dnssec_lookup to return this NSEC3 when asked for NSEC3 of parent.
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

        # Provide a response with an RRSIG that does not validate.
        # We'll patch dns.dnssec.validate to raise ValidationFailure.
        with patch('dns.dnssec.validate', side_effect=dns.dnssec.ValidationFailure("Bogus")):
            # Also need to provide a valid key so the validator attempts validation.
            # We'll mock _get_validated_dnskey to return a dummy key.
            async def fake_get_key(zone):
                if zone == "example.com.":
                    return make_dnskey_rrset("example.com.", 256, 3, 8, b"deadbeef")
                return None
            resolver._get_validated_dnskey = fake_get_key

            # Build a signed message (dummy)
            msg = dns.message.make_query("example.com.", dns.rdatatype.A)
            a_rr = dns.rrset.from_text("example.com.", 3600, "IN", "A", "1.2.3.4")
            msg.answer.append(a_rr)
            rrsig = dns.rrset.from_text(
                "example.com.", 3600, "IN", "RRSIG",
                "A 8 2 3600 20260101000000 20250101000000 12345 example.com. deadbeef"
            )
            msg.answer.append(rrsig)

            with self.assertRaises(dns.dnssec.ValidationFailure):
                await resolver._dnssec_validate_chain("example.com", msg.to_wire(), dnssec_requested=True)

    async def test_chain_validation_limits_keytrap(self):
        """Test that KeyTrap limits (max validations) are enforced."""
        resolver = DNSResolver(
            dnssec_enabled=True,
            dnssec_chain_validation=True,
            dnssec_max_validations=1,  # only one validation allowed
            dnssec_max_dnskey_records=5,
            dnssec_validation_timeout=2.0,
            trust_anchors=None,
        )

        # We need multiple RRsets in the answer to trigger multiple validations.
        # Mock _get_validated_dnskey to return a key.
        async def fake_get_key(zone):
            return make_dnskey_rrset("example.com.", 256, 3, 8, b"deadbeef")
        resolver._get_validated_dnskey = fake_get_key

        # Build a response with two different RRsets (e.g., A and MX) each with RRSIG.
        msg = dns.message.make_query("example.com.", dns.rdatatype.A)
        a_rr = dns.rrset.from_text("example.com.", 3600, "IN", "A", "1.2.3.4")
        msg.answer.append(a_rr)
        rrsig_a = dns.rrset.from_text(
            "example.com.", 3600, "IN", "RRSIG",
            "A 8 2 3600 20260101000000 20250101000000 12345 example.com. deadbeef"
        )
        msg.answer.append(rrsig_a)
        # Add another RRset (MX)
        mx_rr = dns.rrset.from_text("example.com.", 3600, "IN", "MX", "10 mail.example.com.")
        msg.answer.append(mx_rr)
        rrsig_mx = dns.rrset.from_text(
            "example.com.", 3600, "IN", "RRSIG",
            "MX 8 2 3600 20260101000000 20250101000000 12345 example.com. deadbeef"
        )
        msg.answer.append(rrsig_mx)

        # Patch dns.dnssec.validate to always succeed so we don't fail prematurely.
        with patch('dns.dnssec.validate', return_value=None):
            secure, insecure = await resolver._dnssec_validate_chain("example.com", msg.to_wire(), dnssec_requested=True)
            # Because max_validations=1, we only validate one RRset, so the result is False (insecure)
            self.assertFalse(secure)
            self.assertTrue(insecure)  # treated as insecure because limit hit

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

        # Patch _dnssec_validate_old to verify it's called.
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
            dnssec_validation_timeout=0.1,  # very short
            trust_anchors=None,
        )

        # Make _get_validated_dnskey sleep longer than timeout.
        async def slow_get_key(zone):
            await asyncio.sleep(0.5)
            return make_dnskey_rrset("example.com.", 256, 3, 8, b"deadbeef")
        resolver._get_validated_dnskey = slow_get_key

        msg = dns.message.make_query("example.com.", dns.rdatatype.A)
        a_rr = dns.rrset.from_text("example.com.", 3600, "IN", "A", "1.2.3.4")
        msg.answer.append(a_rr)
        rrsig = dns.rrset.from_text(
            "example.com.", 3600, "IN", "RRSIG",
            "A 8 2 3600 20260101000000 20250101000000 12345 example.com. deadbeef"
        )
        msg.answer.append(rrsig)

        secure, insecure = await resolver._dnssec_validate_chain("example.com", msg.to_wire(), dnssec_requested=True)
        self.assertFalse(secure)
        self.assertTrue(insecure)  # timeout leads to insecure


if __name__ == "__main__":
    unittest.main()