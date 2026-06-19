# dosev

`dosev` is a lightweight DNS resolver and forwarder that can listen on UDP/TCP and optionally use DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), DNS-over-QUIC (DoQ), and upstream failover strategies. It also supports blocklists, DNSSEC validation, caching, optimistic stale responses, and optional rebinding protection.

## Features

- DNS server on UDP and TCP
- Optional upstream protocols:
  - UDP/TCP
  - TLS
  - HTTPS (HTTP/1.1, HTTP/2, HTTP/3 auto-detect)
  - QUIC (DoQ)
- DNS caching and optimistic stale serving
- Optional DNSSEC validation with trust anchors
- Blocklist support with local file reloads
- Certificate pinning for TLS-based upstreams
- Optional metrics and logging
- Configuration reload support for some runtime settings

## Requirements

- Python 3.10+
- Dependencies listed in [pyproject.toml](pyproject.toml)

Install runtime dependencies:

```bash
python -m pip install -e .
```

For development/test dependencies:

```bash
python -m pip install -e '.[test]'
```

## Quick start

1. Copy the example configuration:

   ```bash
   cp config/dosev.conf.example config/dosev.conf
   ```

2. Edit the configuration to match your environment.

3. Start the server:

   ```bash
   python -m dosev.cli --config config/dosev.conf
   ```

   Or, if you installed the package entrypoint:

   ```bash
   dosev --config config/dosev.conf
   ```

## Configuration

The default example configuration is available at [config/dosev.conf.example](config/dosev.conf.example).

Key sections include:

- `[server]` — bind address and port
- `[resolver]` — upstream DNS server and transport protocol
- `[cache]` — cache TTL and size
- `[timeouts]` — per-protocol timeout settings
- `[security]` — DNSSEC, pinned certs, rebinding protection, privilege dropping
- `[logging]` and `[metrics]` — observability options
- `[bootstrap]` — bootstrap DNS servers used to resolve upstream hostnames
- `[upstreams]` — additional upstream definitions
- `[blocklists]` — remote blocklists and reload behavior

## How it works

`dosev` accepts DNS requests, checks blocklist/hosts overrides, consults its cache, and then forwards the request to one or more configured upstream resolvers. It can optionally validate DNSSEC responses and apply rebinding protection before returning answers to clients.

## Example: using a custom upstream

You can set a custom upstream in the config file:

```ini
[resolver]
upstream_dns = 1.1.1.1
protocol = udp
```

If you prefer a different transport, switch `protocol` to one of the supported values (`udp`, `tcp`, `tls`, `https`, `quic`).

## Blocklists

Blocklists can be enabled in the `[blocklists]` section. When enabled, `dosev` will:

- download the configured list(s),
- cache them locally, and
- reload them on a schedule or when configured to do so.

## DNSSEC and trust anchors

If you want DNSSEC validation:

1. Enable `dnssec_enabled = true` in the config.
2. Provide a trust anchor file in `trust_anchors_file`.

The resolver will only validate responses when acceptable trust anchors are available.

## Metrics and logging

- Metrics can be enabled in `[metrics]`.
- DNS request logging can be enabled in `[logging]`.
- Use the `verbose` flag to increase debug output.

## Running tests

```bash
python -m pytest
```

## Notes

- Running on port `53` typically requires elevated privileges.
- For production deployments, review the privilege-drop and chroot settings in the config.
- The exact behavior of some advanced settings depends on the environment and upstream support.

