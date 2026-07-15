# [1.8.0] – 2026-07-15

## Added

- **DNSSEC KeyTrap mitigation (CVE-2023-50387)** – protects against CPU exhaustion attacks via malicious DNSSEC responses. Configurable limits:
  - `dnssec_max_validations` – maximum signatures validated per response (default: 32).
  - `dnssec_max_dnskey_records` – maximum DNSKEY records processed per domain (default: 8).
  - `dnssec_validation_timeout` – timeout for validation operations (default: 2.0 seconds).
- **NS record scrubbing (CVE-2025-11411, RFC 2181)** – prevents cache poisoning by removing unsolicited NS records from the authority section. Configurable via `dns_scrub_unsolicited_ns` (default: true).

## Changed

- **Refactored `_dnssec_validate`** – now tracks validation count and enforces limits.
- **Refactored `_load_trust_anchors`** – limits DNSKEY records per domain.
- **Updated `_process_upstream_response`** – applies NS scrubbing before caching.

## Security

- **KeyTrap mitigation** – prevents DoS via malicious DNSSEC responses.
- **Cache poisoning prevention** – scrubs unsolicited NS records (RFC 2181).

## Documentation

- Added new `[security]` options to `config-reference.md`.
- Updated `architecture.md` with security features.
- Updated `README.md` features table.

## Testing

- New test suite: `test_dnssec_keytrap.py` (4 tests).
- New test suite: `test_ns_scrub.py` (7 tests).
- All 115 tests pass on Windows, macOS, and Linux (Python 3.10–3.14).
