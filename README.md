# dosev
A DNS resolver.

## Documentation

- [Quickstart](docs/quickstart.md)
- [Architecture](docs/architecture.md)
- [Configuration Reference](docs/config-reference.md)
- [Deployment Tips](docs/deployment-tips.md)

### Encrypted Server Endpoints (DoT & DoH)

Status: Currently the server listens on plain UDP/TCP only.

Why: Clients increasingly expect secure transports.

How: The server can now optionally expose:
- DNS-over-TLS (DoT) on port `853`
- DNS-over-HTTPS (DoH) on port `443`

Configuration is available under the `[resolver]` section:
- `dns_enable_dot = true`
- `dns_dot_cert_file = /path/to/cert.pem`
- `dns_dot_key_file = /path/to/key.pem`
- `dns_enable_doh = true`
- `dns_doh_cert_file = /path/to/cert.pem`
- `dns_doh_key_file = /path/to/key.pem`
- `dns_doh_path = /dns-query`

These listeners reuse the existing resolver forwarding logic so secure transports behave like the existing UDP/TCP handlers.
