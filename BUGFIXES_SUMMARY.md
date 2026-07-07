# v1.4.0 (2026-07-08)

## Features

- **HTTP/3 server**: New `dns_enable_http3` option to serve DNS over HTTPS using HTTP/3 (aioquic).
- **DoQ connection pooling**: QUIC connections are reused across queries, reducing latency and handshake overhead.
- **IPv6 stripping**: New `strip_ipv6_records` option to remove AAAA records from responses.
- **Default config**: Removed deprecated `upstream_dns` and `protocol`; now uses `[upstreams]` section with `ip` and full comments.

## Bug Fixes

- **DoQ**: Fixed `closed` attribute access and connection pooling logic.
- **HTTP/3 tests**: Corrected mock setups to reliably test request handling.

## Other

- Documentation updated for all new features.
- All 85 tests now pass on Windows, macOS, and Linux.
