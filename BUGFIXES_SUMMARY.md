# v1.1.0 (2026-07-07)

## Bug Fixes

- **RFC 6891:** Preserve client’s EDNS payload size (no longer capped to 4096).
- **RFC 4035:** DNSSEC validation now treats unsigned domains as insecure (AD=0) instead of failing.
- **RFC 2308:** Negative cache now respects SOA MINIMUM TTL from authority section.
- **Truncation:** Set TC bit in UDP responses when reply exceeds client’s advertised payload.
- **Stale Cache:** Fixed `_set_response_ttl` to correctly reduce TTL for stale responses (removed invalid `rd.ttl` assignment).

## Test Improvements

- Fixed `test_dnssec_bogus_raises` to mock validation properly.
- Adjusted integration tests for cross‑platform reliability.
- All 72 tests now pass on CI (Windows, macOS, Linux).