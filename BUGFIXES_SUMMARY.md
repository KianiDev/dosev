# v1.3.0 (2026-07-07)

## Breaking Changes

- **Resolver constructor**: Removed `upstream_dns` and `protocol` parameters. All upstreams must now be defined in the `upstreams` list.
- **Configuration**: The `[resolver]` section no longer uses `upstream_dns` or `protocol`. Upstreams are defined in `[upstreams]`.

## Features

- **Upstream `ip` field**: Specify a fixed IP address for each upstream to skip DNS resolution.
- **Bootstrap DNS**: Fully integrated – resolvers use bootstrap servers (or system resolver) to resolve upstream domain names when no IP is provided.
- **Auto‑generate default config**: On first run, dosev creates a default `dosev.conf` in the OS‑specific user config directory:
  - Windows: `%APPDATA%\dosev\dosev.conf`
  - macOS: `~/Library/Application Support/dosev/dosev.conf`
  - Linux: `~/.config/dosev/dosev.conf`
- **Config comments**: The auto‑generated config now includes detailed comments for all options.

## Bug Fixes

- **RFC 6891**: Preserve client’s EDNS payload size (no longer capped to 4096).
- **RFC 4035**: DNSSEC validation now treats unsigned domains as insecure (AD=0) instead of failing.
- **RFC 2308**: Negative cache now respects SOA MINIMUM TTL from authority section.
- **Truncation**: Set TC bit in UDP responses when reply exceeds client’s advertised payload.
- **Stale Cache**: Fixed `_set_response_ttl` to correctly reduce TTL for stale responses.
- **DoQ**: Fixed undefined `QueryTimeout` (now uses `TimeoutError`).

## Test Improvements

- Added comprehensive tests for upstream configuration and bootstrap logic.
- All 78 tests now pass on Windows, macOS, and Linux.
